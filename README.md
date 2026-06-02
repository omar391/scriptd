# scriptd

`scriptd` is a lightweight macOS automation supervisor for small TypeScript modules. It installs a single user-level `launchd` agent, loads modules from `modules/*`, manages long-running daemons and scheduled jobs, and exposes status, health, logs, and reload controls through a simple shell entrypoint.

The project is intentionally minimal:

- no build step
- no root-level runtime dependencies in the repo
- no external framework for module loading
- plain YAML for service and module configuration

## What It Does

- Installs one LaunchAgent from `service.yaml`
- Starts and stops modules based on enabled flags
- Supports both daemon modules and interval modules
- Watches `service.yaml` for live reloads when `watch: true`
- Writes shared logs plus per-module logs
- Persists runtime state to a JSON file for `status`
- Lets modules report health and structured metrics

## Architecture

```text
scriptd.sh
  -> src/main.ts
      -> install/uninstall/reload/status/test commands
      -> run root -> src/supervisor.ts
          -> discover modules from modules/<name>/
          -> load module.ts + module.yaml
          -> start daemons or schedule interval jobs
          -> write state.json and logs
```

Repo layout:

```text
.
├── scriptd.sh
├── service.yaml
├── src/
│   ├── main.ts
│   ├── supervisor.ts
│   ├── module-runner.ts
│   ├── config.ts
│   ├── status.ts
│   └── tests/
└── modules/
    ├── wifi-monitor/
    ├── cpu-monitor/
    └── brew-manager/
```

## Requirements

`scriptd` is macOS-specific. The current source relies on:

- `launchctl` / `launchd`
- one runtime that can execute `src/main.ts`
  - `bun`
  - `node --experimental-strip-types`
  - `npx tsx`
- standard macOS command-line tools used by the bundled modules

Module-specific tools:

- `wifi-monitor`: `networksetup`, `ping`, and either the private `airport` CLI or the built-in `swift` CoreWLAN fallback
- `cpu-monitor`: `ps` and the ability to signal processes
- `brew-manager`: Homebrew, `security`, and `sudo`

## Quick Start

1. Clone the repo and keep the checkout somewhere stable.
2. Review and edit [`service.yaml`](./service.yaml).
3. Review any module-specific settings in `modules/<module>/module.yaml`.
4. Run one-time module setup when needed:

```bash
./scriptd.sh setup brew-manager
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
- The LaunchAgent points at this checkout's `scriptd.sh`, so if you move the repo after installing, reinstall the service.

## Commands

```bash
./scriptd.sh start root        # install or update the LaunchAgent, then start it
./scriptd.sh restart root      # install or update the LaunchAgent, then restart it
./scriptd.sh stop root         # stop the LaunchAgent but keep it installed
./scriptd.sh uninstall root    # remove the LaunchAgent
./scriptd.sh run <module>      # run one module directly
./scriptd.sh setup <module>    # run one-time module setup
./scriptd.sh reload            # reload service.yaml in the running supervisor
./scriptd.sh status            # print launchd + module status
./scriptd.sh test              # run unit and integration tests
```

`scriptd.sh` tries the available runtimes in this order:

1. `bun`
2. `node --experimental-strip-types`
3. `npx tsx`

## Service Configuration

Global service configuration lives in [`service.yaml`](./service.yaml):

```yaml
label: com.omar.scriptd
log_dir: ~/Library/Logs/scriptd
watch: true
modules:
  wifi-monitor:
    enabled: false
    schedule:
      every_minutes: 5
  cpu-monitor:
    enabled: false
    schedule:
      every_minutes: 1
  brew-manager:
    enabled: true
    schedule:
      every_hours: 12
```

Fields:

- `label`: LaunchAgent label
- `log_dir`: shared log directory for root and module logs
- `watch`: when `true`, the supervisor watches `service.yaml` and reapplies config automatically
- `modules.<name>.enabled`: desired on/off state for each discovered module
- `modules.<name>.schedule`: interval-module runtime schedule

Schedules are local-time and wall-clock anchored. You can use exactly one trigger per module:

```yaml
schedule:
  every_seconds: 30
  # or: every_minutes: 5
  # or: every_hours: 12
  # or: daily_at: "09:30"
  # or: cron: "0 */5 * * * *"
```

Optional gates can restrict when a trigger is allowed to start:

```yaml
schedule:
  daily_at: "09:30"
  weekdays:
    - mon
    - wed
    - fri
  window:
    start: "09:00"
    end: "17:00"
```

Module-specific algorithm settings still live in each module's `module.yaml`.

## Bundled Modules

### `wifi-monitor`

- Mode: `interval`
- Default: disabled
- Default schedule: every 5 minutes
- Purpose: scans nearby Wi-Fi networks, scores candidates, and switches to the best allowed SSID
- Inputs: preferred network list or `ssids` configured in `modules/wifi-monitor/module.yaml`
- Tuning: dwell time, ping target, manual SSID priority, band bonuses, RSSI offset, switch threshold

See [`modules/wifi-monitor/README.md`](./modules/wifi-monitor/README.md).

### `cpu-monitor`

- Mode: `interval`
- Default: disabled
- Default schedule: every 1 minute
- Purpose: tracks processes that stay above a CPU threshold and kills them after a sustained time limit
- Tuning: CPU threshold, time limit, excluded app names

See [`modules/cpu-monitor/README.md`](./modules/cpu-monitor/README.md).

### `brew-manager`

- Mode: `interval`
- Default: enabled
- Default schedule: every 12 hours
- Purpose: runs `brew update`, formula upgrades, cask upgrades, repair fallback flow, and `brew cleanup`
- Setup: stores a sudo password in Keychain, writes an askpass helper, and installs sudoers rules

See [`modules/brew-manager/README.md`](./modules/brew-manager/README.md).

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

## Runtime Behavior

- `start root` and `restart root` write the LaunchAgent plist and call `launchctl load -w`, so a disabled login item is re-enabled.
- Daemon modules are started immediately when enabled.
- Interval modules are scheduled from `service.yaml`; `intervalMs` and `interval_seconds` remain the module's fallback cadence.
- Interval runs do not overlap.
- Daemon modules are restarted after crashes with a short delay.
- Disabling a module aborts its signal and calls the module's optional `stop()` hook.
- `reload` sends `SIGHUP` to the running supervisor or asks `launchctl` to do so.

## Writing A Module

Each module lives in `modules/<id>/` and must include:

- `module.ts`
- `module.yaml`

Rules enforced by the loader:

- folder name, `module.yaml` `id`, and `module.ts` `id` must match
- `mode` must match between `module.ts` and `module.yaml`
- daemon modules must implement `start()`
- interval modules must implement `runOnce()`
- interval modules must define both:
  - `intervalMs` in `module.ts`
  - `interval_seconds` in `module.yaml`
- those interval values must match exactly

Minimal interval example:

```ts
import type { RootServiceModule } from "../../src/interfaces.ts";

const modulePlugin: RootServiceModule = {
  id: "example-job",
  mode: "interval",
  intervalMs: 60_000,
  async runOnce(ctx) {
    ctx.log.info("example-job ran");
  },
};

export default modulePlugin;
```

Matching manifest:

```yaml
id: example-job
mode: interval
interval_seconds: 60
display_name: Example Job
```

Useful module hooks:

- `loadConfig(ctx)`
- `setup(ctx)`
- `start(ctx, config)`
- `stop(ctx)`
- `runOnce(ctx, config)`
- `status(ctx)`
- `health(ctx)`

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
- The root `package.json` defines scripts only; the supervisor executes TypeScript directly.
- The bundled modules are macOS-oriented personal automations, but the module interface is generic enough for additional local services and scheduled tasks.

## License

No license file is present in this repo at the time of writing.
