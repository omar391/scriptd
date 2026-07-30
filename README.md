# scriptd

`scriptd` is a lightweight macOS automation supervisor for native Rust modules. It installs a single user-level `launchd` agent, loads modules from `modules/*`, evaluates global Boolean triggers, and exposes status, health, logs, and configuration controls through a simple shell entrypoint.

The project is intentionally minimal:

- no root-level runtime dependencies in the repo
- no external framework for module loading
- plain YAML for service and module configuration

## What It Does

- Installs one LaunchAgent from `service.yaml`
- Starts and stops modules based on enabled flags
- Dispatches task modules from global recursive trigger expressions
- Watches `service.yaml` and module manifests for live reloads when `watch: true`
- Writes shared logs plus per-module logs
- Persists runtime state to a JSON file for `status`
- Lets modules report health and structured metrics

## Architecture

```text
scriptd.sh
  -> target/release/scriptd (or `cargo run --release`)
      -> start/stop/uninstall/status/test commands
      -> run root -> src/main.rs -> src/supervisor.rs
          -> discover modules from modules/<name>/
          -> load service.yaml + typed modules/<name>/module.yaml
          -> sample shared sensors and evaluate global triggers
          -> dispatch typed task incidents without overlap
          -> write state.json and logs
```

Repo layout:

```text
.
	├── scriptd.sh
	├── assets/
    ├── service.yaml
    ├── src/
    │   ├── main.rs
    │   ├── supervisor.rs
    │   ├── launchd.rs
    │   ├── config.rs
    │   ├── status.rs
    │   ├── modules.rs
    │   └── triggers/
└── modules/
    ├── mwifi/
    ├── miwatch/
    ├── mcpu/
    └── mbrew/
```

## Requirements

`scriptd` is macOS-specific. The current source relies on:

- `launchctl` / `launchd`
- one Rust binary: `target/release/scriptd` (or `cargo run --release -- ...`)
- standard macOS command-line tools used by the bundled modules

Module-specific tools:

- `mwifi`: `networksetup`, `ping`, and `airport` CLI fallback path
- global Wi-Fi triggers: CoreWLAN events plus rate-limited visibility scans
- `miwatch`: `curl` and optional `adb` for autonomous session collection
- `mcpu`: sysinfo process inspection plus command-level signal support when needed
- `mbrew`: Homebrew, `security`, and `sudo`

## Quick Start

1. Clone the repo and keep the checkout somewhere stable.
2. Review and edit [`service.yaml`](./service.yaml).
3. Review any module-specific settings in `modules/<module>/module.yaml`.
4. Run one-time module setup when needed:

```bash
./scriptd.sh config mbrew
```

5. Install the supervisor LaunchAgent:

```bash
./scriptd.sh start root
```

6. Check runtime status:

```bash
./scriptd.sh status
```

Notes:

- `root` means the top-level `scriptd` service, not the root user.
- The LaunchAgent runs through a generated `Scriptd.app` wrapper in `~/Library/Application Support/scriptd` so macOS Login Items can show a real `scriptd` icon. If you move the repo after starting the service, run `./scriptd.sh start root`.

## Commands

```bash
./scriptd.sh start root        # install or update the LaunchAgent, then start it
./scriptd.sh stop root         # stop the LaunchAgent but keep it installed
./scriptd.sh uninstall root    # remove the LaunchAgent
./scriptd.sh run <module>      # run one module directly
./scriptd.sh miwatch session refresh # renew Xiaomi serviceToken directly
./scriptd.sh config <module>   # run setup and enable the module
./scriptd.sh config <module> --enable|--disable
./scriptd.sh config <module> show # print the module's service policy
./scriptd.sh status            # print launchd + module status
./scriptd.sh schema service    # print the generated service JSON Schema
./scriptd.sh schema module miwatch # print one module JSON Schema
./scriptd.sh test              # run unit and integration tests
```

`scriptd.sh` uses the compiled binary when present and falls back to `cargo run --release` for development.

## Service Configuration

Global orchestration configuration lives in [`service.yaml`](./service.yaml).
It owns daemon settings, module enablement, schedules, and triggers. Module
implementation settings live in the corresponding versioned
`modules/<module>/module.yaml` file.

```yaml
version: 1
service:
  label: com.omar.scriptd
  log_dir: ~/Library/Logs/scriptd
  watch: true
modules:
  mwifi:
    enabled: false
    triggers:
      sample:
        fire: { mode: every_match }
        when:
          all:
            - schedule: { every_minutes: 5 }
            - time_window:
                timezone: Asia/Dhaka
                start: "00:00"
                end: "23:59"
```

Fields:

- `version`: strict service document version; current version is `1`
- `service.label`: LaunchAgent label
- `service.log_dir`: shared log directory for root and module logs
- `service.watch`: when `true`, the supervisor watches service and module YAML files
- `modules.<name>.enabled`: desired on/off state for each discovered module
- `modules.<name>.triggers.<id>`: a rule owned by that module; its canonical runtime ID is `<module>.<id>`

`when` and a latched rule's `reset.when` are recursive, non-empty `all`/`any`
trees. Leaves are:

- `schedule`: exactly one of `every_seconds`, `every_minutes`, `every_hours`,
  `daily_at`, or `cron`. A schedule is a true pulse at its deadline. A schedule
  required by every Boolean path gates evaluation; a schedule in one `any`
  branch does not suppress independently sufficient sibling branches.
- `time_window`: IANA timezone, optional weekdays, and a half-open window;
  crossing midnight is supported. For an overnight window, `weekdays` names
  the day on which the window starts.
- `wifi_power`: `on` or `off`
- `wifi_ssid`: `connected`, `disconnected`, `available`, or `unavailable`
- `process_network`: application selectors, `sum`, and a bytes-per-second
  threshold measured from a one-second external-interface delta sample.
  Applications are a union, so one process matching multiple selectors is
  counted once. `Codex` includes trusted Codex components owned by either
  `Codex.app` or the current `ChatGPT.app` host.

Conditions evaluate to `true`, `false`, or `unknown`. Sensor failures are
`unknown` and cannot authorize an action. `fire.mode: every_match` dispatches
each matching evaluation. `fire.mode: latched` supports sustained match/reset
counts and durations, persists the incident before dispatch, and cannot fire
again until its reset expression succeeds. Trigger-level `after` applies to
repeated observations: for the production 30-second `miwatch` schedule, three
matching one-second network samples span at least 60 seconds. Traffic between
samples is not assumed, and a missed required schedule pulse breaks the streak.

The complete `miwatch` expression in [`service.yaml`](./service.yaml) is:

```text
schedule AND SSID unavailable AND
  (time-window OR Codex desktop network activity >= 1 KiB/s)
```

The latch resets after the SSID is visible in two observations spanning at
least 30 seconds. Association is not required: visibility is the direct
recovery inverse of the outage condition, while the Mac may remain connected
through another route.

Each module manifest has a versioned metadata and typed `settings` object:

```yaml
# yaml-language-server: $schema=../../schemas/v1/modules/mwifi.schema.json
version: 1
module:
  id: mwifi
  display_name: Wi-Fi Monitor
  mode: task
settings:
  min_dwell: 180
  ping_target: 1.1.1.1
```

Generated JSON Schemas are checked in under `schemas/v1/`; the modelines
in each YAML file provide editor validation.

Update module enablement with `config <module>`. Trigger expressions are
YAML-authored only:

```bash
./scriptd.sh config mwifi --enable
./scriptd.sh config mcpu --disable
./scriptd.sh config mwifi show
```

Run `./scriptd.sh start root` after changing config flags to install/update the LaunchAgent and restart it if it is already running. When `watch: true`, a running supervisor also picks up service and module YAML edits automatically.

## Bundled Modules

### `mwifi`

- Mode: `task`
- Default: disabled
- Default schedule: every 5 minutes
- Purpose: scans nearby Wi-Fi networks, scores candidates, and switches to the best allowed SSID
- Inputs: preferred network list or `ssids` configured in `modules/mwifi/module.yaml`
- Tuning: dwell time, ping target, manual SSID priority, band bonuses, RSSI offset, switch threshold

See [`modules/mwifi/README.md`](./modules/mwifi/README.md).

### `miwatch`

- Mode: `task`
- Default: disabled
- Trigger: every 30 seconds inside the configured Boolean outage expression
- Purpose: detect loss of `knight_riders_5G` and, only after an evidence-backed
  API profile is supplied, request one authenticated remote router reboot when
  the outage is inside the 05:00–02:00 window or the Codex desktop components
  have active external network traffic.
- Safety: fail-closed until the Mi WiFi request has static and dynamic evidence;
  ambiguous reboot responses are never retried during the same outage.

See [`modules/miwatch/README.md`](./modules/miwatch/README.md).

### `mcpu`

- Mode: `task`
- Default: disabled
- Default schedule: every 1 minute
- Purpose: tracks processes that stay above a CPU threshold and kills them after a sustained time limit
- Tuning: CPU threshold, time limit, excluded app names

See [`modules/mcpu/README.md`](./modules/mcpu/README.md).

### `mbrew`

- Mode: `task`
- Default: enabled
- Default schedule: every 12 hours
- Purpose: runs `brew update`, formula upgrades, cask upgrades, repair fallback flow, and `brew cleanup`
- Setup: stores a sudo password in Keychain, writes an askpass helper, and installs sudoers rules

See [`modules/mbrew/README.md`](./modules/mbrew/README.md).

## Logs And State

By default, `service.yaml` points logs to `~/Library/Logs/scriptd`.

Expected files:

- `scriptd.log`
- `scriptd.err`
- `<module>.log`
- `<module>.err`

Runtime state is written to:

```text
~/Library/Application Support/scriptd/state.json
```

The `status` command combines:

- `launchctl list` output for the configured LaunchAgent label
- the persisted supervisor state file
- module health, status messages, run counters, restart counters, and metrics
- each trigger's target, phase, counters, last evaluation/fire, next wake, and
  redacted observation error

## Runtime Behavior

- `start root` writes the LaunchAgent plist, re-enables the launchd item, and starts or restarts it as needed.
- The LaunchAgent points at `~/Library/Application Support/scriptd/Scriptd.app/Contents/MacOS/scriptd`; that launcher executes this checkout's `scriptd.sh run root`.
- Trigger deadlines, CoreWLAN events, configuration reloads, and a 30-second
  sensor fallback wake the supervisor loop.
- Active SSID visibility scans are shared and rate-limited. External network
  deltas are attributed by PID to every executable owned by a configured
  `.app` bundle, including helpers; process arguments are never inspected or
  logged.
- Task runs do not overlap. Pending work is coalesced by trigger ID.
- Trigger phase, debounce/reset counters, incident generation, pending
  dispatch, errors, and schedule deadlines are atomically persisted.
- Invalid hot reloads retain the last valid trigger configuration.
- Disabling a module stops its runtime scheduling immediately and updates module state.
- With `watch: true`, `service.yaml` changes are applied by the running supervisor automatically.
- `run <module>` is explicit manual execution and bypasses global conditions.
  Module-specific safety checks still apply.

## Writing A Module

Each module lives in `modules/<id>/` and must include:

- `module.rs`
- `module.yaml`

Rules enforced by the loader:

Each module folder is validated against a single manifest:

```yaml
id: example-job
mode: task
display_name: Example Job
```

Runtime hooks in Rust are module-specific but follow the same conceptual shape in this port:

- `setup(context)`
- `run_once(context)`
- `status() -> Option<(ModuleStatus, ModuleHealth)>`

## Testing

Run the project test suite with:

```bash
./scriptd.sh test
```

The repo includes tests for:

- YAML parsing and config validation
- module discovery and manifest consistency
- runtime fallback behavior in `scriptd.sh`
- install/uninstall and command integration flows
- module helper logic for the bundled modules

## Operational Notes

- This project is designed around a user LaunchAgent in `~/Library/LaunchAgents`.
- Install the LaunchAgent from the primary checkout; `start root` rejects linked git worktrees so the service cannot retain a disposable worktree path.
- The repo is built as a single Rust binary.
- The bundled modules are macOS-oriented personal automations, but the module interface is generic enough for additional local services and scheduled tasks.

## License

No license file is present in this repo at the time of writing.
