cpu-monitor
===========

This is a small macOS CPU monitor that watches running processes, tracks ones that stay above a CPU threshold, and kills them if they remain above that threshold for too long.

How it works
- Polls `ps aux` every 30 seconds.
- Tracks processes that exceed 50% CPU.
- Kills a tracked process if it stays above the threshold for 10 minutes.
- Excludes common system and interactive apps such as Finder, Dock, Terminal, Activity Monitor, `kernel_task`, and `loginwindow`.

Files
- `module.ts` — TypeScript plugin implementation.
- `module.yaml` — the single module manifest/config file.

Configuration
- `CPU_THRESHOLD` — CPU percentage required before tracking starts. Default `50`.
- `CHECK_INTERVAL` — Seconds between scans. Default `30`.
- `TIME_LIMIT` — Seconds a process may stay above the threshold before it is killed. Default `600`.
- `EXCLUDE_APPS` — Array of process names that are never killed.

Usage
- `./scriptd.sh run cpu-monitor`
- Enable or disable it from `service.yaml`

Logging
- Managed by `scriptd` under the shared log directory from `service.yaml`.

Notes
- The module is a long-running daemon plugin.
- It only tracks PIDs in memory while it is running.
