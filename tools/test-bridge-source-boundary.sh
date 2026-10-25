#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CHECKER="$SCRIPT_DIR/check-bridge-source-boundary.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/scriptd-source-boundary.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

FIXTURE="$TEST_ROOT/repository"
mkdir -p "$FIXTURE/crates/scriptd-bridge/src" \
  "$FIXTURE/crates/scriptd-bridge-protocol/src"
: > "$FIXTURE/Cargo.toml"
cp "$CHECKER" "$FIXTURE/check-bridge-source-boundary.sh"
chmod +x "$FIXTURE/check-bridge-source-boundary.sh"

(
  cd "$FIXTURE"
  ./check-bridge-source-boundary.sh >/dev/null
)

printf 'struct ServiceConfig;\n' > "$FIXTURE/crates/scriptd-bridge/src/main.rs"
if (cd "$FIXTURE" && ./check-bridge-source-boundary.sh) >"$TEST_ROOT/forbidden.out" 2>&1; then
  echo 'boundary checker accepted a forbidden symbol under crates/' >&2
  exit 1
fi
if ! grep -q 'product runtime symbols remain in the public crate sources' "$TEST_ROOT/forbidden.out"; then
  cat "$TEST_ROOT/forbidden.out" >&2
  echo 'boundary checker failed for an unexpected reason' >&2
  exit 1
fi

mkdir -p "$TEST_ROOT/fake-bin"
cat > "$TEST_ROOT/fake-bin/grep" <<'EOF'
#!/bin/sh
exit 2
EOF
chmod +x "$TEST_ROOT/fake-bin/grep"
set +e
scan_output=$(cd "$FIXTURE" && PATH="$TEST_ROOT/fake-bin:$PATH" ./check-bridge-source-boundary.sh 2>&1)
scan_status=$?
set -e
case "$scan_output" in
  *"could not scan crate sources"*) ;;
  *)
    printf '%s\n' "$scan_output" >&2
    echo 'boundary checker did not report a source scan error' >&2
    exit 1
    ;;
esac
if [ "$scan_status" -ne 2 ]; then
  printf '%s\n' "$scan_output" >&2
  echo 'boundary checker did not report a source scan error' >&2
  exit 1
fi

echo 'bridge source-boundary fixtures passed'
