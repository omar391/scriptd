mcpu
===========

This is a small macOS CPU monitor that checks running processes, tracks ones that stay above a CPU threshold, and kills them if they remain above that threshold for too long.

How it works
- Runs one scan each time `scriptd` schedules it from `service.yaml`.
- Tracks processes that exceed 50% CPU.
- Kills a tracked process if it stays above the threshold for 10 minutes.
- Excludes common system and interactive apps such as Finder, Dock, Terminal, Activity Monitor, `kernel_task`, and `loginwindow`.

Files
- `module.rs` — Rust plugin implementation.
- `module.yaml` — the single module manifest/config file.

Configuration
- `CPU_THRESHOLD` — CPU percentage required before tracking starts. Default `50`.
- `TIME_LIMIT` — Seconds a process may stay above the threshold before it is killed. Default `600`.
- `EXCLUDE_APPS` — Array of process names that are never killed.

Usage
- `./scriptd.sh run mcpu`
- Enable or disable it from `service.yaml`
- Ongoing cadence is configured in `service.yaml` under `modules.mcpu.schedule`.

Logging
- Managed by `scriptd` under the shared log directory from `service.yaml`.

Notes
- The module is an interval plugin.
- It tracks PIDs in memory while the root supervisor is running.
