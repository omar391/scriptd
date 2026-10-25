#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 - "$SCRIPT_DIR" <<'PY'
import os
import subprocess
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1])
preinstall = (script_dir / "bridge/pkg-scripts/preinstall").read_text()
postinstall = (script_dir / "bridge/pkg-scripts/postinstall").read_text()

with tempfile.TemporaryDirectory(
    prefix="scriptd-installer-validation-",
    dir=os.environ.get("TMPDIR", "/tmp"),
) as temporary:
    root = Path(temporary)
    mock_bin = root / "mock-bin"
    mock_bin.mkdir()
    log_path = root / "calls.log"
    plist_path = root / "com.astronlab.scriptd.bridge.plist"
    support_path = root / "support"
    binary_path = mock_bin / "scriptd-bridge"

    mock_command = mock_bin / "mock-command"
    mock_command.write_text(
        "#!/bin/sh\n"
        "name=${0##*/}\n"
        "printf '%s %s\\n' \"$name\" \"$*\" >> \"$MOCK_LOG\"\n"
        "if [ \"$name\" = launchctl ]; then\n"
        "  case \"${1-}\" in\n"
        "    print)\n"
        "      case \"${MOCK_LAUNCHCTL_MODE-}\" in\n"
        "        absent) echo 'Bad request.' >&2; echo 'Could not find service \"com.astronlab.scriptd.bridge\" in domain for system' >&2; exit 113 ;;\n"
        "        query-failure) echo 'Service domain unavailable' >&2; exit 5 ;;\n"
        "      esac\n"
        "      ;;\n"
        "    bootout)\n"
        "      case \"${MOCK_LAUNCHCTL_MODE-}\" in\n"
        "        absent|failure) echo 'Boot-out failed: 5: Input/output error' >&2; exit 5 ;;\n"
        "      esac\n"
        "      ;;\n"
        "  esac\n"
        "fi\n"
        "exit 0\n"
    )
    mock_command.chmod(0o755)
    command_names = ["launchctl", "mkdir", "chown", "chmod", "plutil", "codesign"]
    for name in command_names:
        (mock_bin / name).symlink_to(mock_command)
    binary_path.symlink_to(mock_command)

    rendered_preinstall = preinstall.replace(
        "/bin/launchctl", str(mock_bin / "launchctl")
    ).replace(
        "/Library/LaunchDaemons/com.astronlab.scriptd.bridge.plist",
        str(plist_path),
    )
    rendered_postinstall = postinstall
    replacements = {
        "/usr/local/libexec/scriptd-bridge": str(binary_path),
        "/Library/LaunchDaemons/com.astronlab.scriptd.bridge.plist": str(plist_path),
        "/Library/Application Support/scriptd": str(support_path),
        "/bin/launchctl": str(mock_bin / "launchctl"),
        "/bin/mkdir": str(mock_bin / "mkdir"),
        "/usr/sbin/chown": str(mock_bin / "chown"),
        "/bin/chmod": str(mock_bin / "chmod"),
        "/usr/bin/plutil": str(mock_bin / "plutil"),
        "/usr/bin/codesign": str(mock_bin / "codesign"),
    }
    for original, replacement in replacements.items():
        rendered_postinstall = rendered_postinstall.replace(original, replacement)

    preinstall_path = root / "preinstall"
    postinstall_path = root / "postinstall"
    preinstall_path.write_text(rendered_preinstall)
    postinstall_path.write_text(rendered_postinstall)
    preinstall_path.chmod(0o755)
    postinstall_path.chmod(0o755)

    environment = os.environ.copy()
    environment["MOCK_LOG"] = str(log_path)

    def run(path: Path, mode: str) -> subprocess.CompletedProcess[str]:
        environment["MOCK_LAUNCHCTL_MODE"] = mode
        return subprocess.run(
            ["/bin/sh", str(path)],
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    log_path.write_text("")
    fresh_preinstall = run(preinstall_path, "absent")
    if fresh_preinstall.returncode != 0:
        raise SystemExit(f"fresh preinstall failed: {fresh_preinstall.stderr}")
    fresh_postinstall = run(postinstall_path, "success")
    if fresh_postinstall.returncode != 0:
        raise SystemExit(f"fresh postinstall failed: {fresh_postinstall.stderr}")
    fresh_calls = log_path.read_text().splitlines()
    fresh_launch = [line for line in fresh_calls if line.startswith("launchctl ")]
    if len(fresh_launch) != 3 or not fresh_launch[0].startswith("launchctl print "):
        raise SystemExit(f"fresh install did not handle the absent service: {fresh_launch}")
    if not fresh_launch[1].startswith("launchctl bootstrap ") or not fresh_launch[2].startswith(
        "launchctl kickstart -k "
    ):
        raise SystemExit(f"fresh install did not bootstrap and activate the service: {fresh_launch}")
    if any(line.startswith("launchctl bootout ") for line in fresh_launch):
        raise SystemExit(f"fresh install attempted to boot out an absent service: {fresh_launch}")

    log_path.write_text("")
    upgrade_preinstall = run(preinstall_path, "success")
    if upgrade_preinstall.returncode != 0:
        raise SystemExit(f"upgrade preinstall failed: {upgrade_preinstall.stderr}")
    upgrade_postinstall = run(postinstall_path, "success")
    if upgrade_postinstall.returncode != 0:
        raise SystemExit(f"upgrade postinstall failed: {upgrade_postinstall.stderr}")
    upgrade_launch = [
        line for line in log_path.read_text().splitlines() if line.startswith("launchctl ")
    ]
    if len(upgrade_launch) != 4 or not upgrade_launch[0].startswith("launchctl print "):
        raise SystemExit(f"upgrade did not boot out the existing service first: {upgrade_launch}")
    if not upgrade_launch[1].startswith("launchctl bootout "):
        raise SystemExit(f"upgrade did not boot out the existing service after checking it: {upgrade_launch}")
    if not upgrade_launch[2].startswith("launchctl bootstrap ") or not upgrade_launch[3].startswith(
        "launchctl kickstart -k "
    ):
        raise SystemExit(f"upgrade did not activate the replacement service: {upgrade_launch}")

    log_path.write_text("")
    query_failure = run(preinstall_path, "query-failure")
    query_calls = [
        line for line in log_path.read_text().splitlines() if line.startswith("launchctl ")
    ]
    if query_failure.returncode != 5 or "could not inspect service" not in query_failure.stderr:
        raise SystemExit(
            "preinstall suppressed a launchctl service-query failure: "
            f"status={query_failure.returncode}, stderr={query_failure.stderr!r}"
        )
    if len(query_calls) != 1 or not query_calls[0].startswith("launchctl print "):
        raise SystemExit(f"preinstall continued after a service-query failure: {query_calls}")

    log_path.write_text("")
    failed_preinstall = run(preinstall_path, "failure")
    if failed_preinstall.returncode != 5 or "bootout failed" not in failed_preinstall.stderr:
        raise SystemExit(
            "preinstall suppressed a real launchctl bootout failure: "
            f"status={failed_preinstall.returncode}, stderr={failed_preinstall.stderr!r}"
        )
    failure_calls = [
        line for line in log_path.read_text().splitlines() if line.startswith("launchctl ")
    ]
    if len(failure_calls) != 2 or not failure_calls[1].startswith("launchctl bootout "):
        raise SystemExit(f"preinstall did not preserve registered-service bootout failure: {failure_calls}")

print("bridge installer lifecycle fixtures passed")
PY
