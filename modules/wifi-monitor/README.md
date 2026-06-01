wifi-monitor
===========

This is a small macOS Wi‑Fi monitor that filters to known SSIDs, scores each candidate, and switches to the highest-scoring one.

It prefers the legacy `airport -s` scan output when available, and falls back to a CoreWLAN scan through `swift` on newer macOS setups where the private `airport` binary is missing.

How ranking works
- If `WIFI_MONITOR_SSIDS` is set, only those SSIDs are considered.
- If `WIFI_MONITOR_SSIDS` is empty, the monitor falls back to the system preferred Wi-Fi network list from `networksetup`.
- Each candidate gets a score made from:
  - `5g` band bonus: `+100`
  - RSSI strength: `rssi + 100`, clamped to `0..100`
  - Ping penalty: subtract up to `30` based on the configured ping target and `WIFI_MONITOR_PING_WEIGHT`
- A higher score wins.
- The monitor keeps the current network if it is still the best option or if the new best score is not at least `10` points better.
- It also respects `WIFI_MONITOR_MIN_DWELL`, so it will not switch again until the dwell window has passed.

Files
- `module.ts` — TypeScript plugin implementation.
- `module.yaml` — the single module manifest/config file.

Usage
- `./scriptd.sh run wifi-monitor`
- Enable or disable it from `service.yaml`

Configuration
- Edit `module.yaml` for the default config, or override values through environment variables.
- Useful env vars:
  - `WIFI_MONITOR_SSIDS` — comma-separated SSIDs to manage.
  - `WIFI_MONITOR_INTERVAL` — scan interval in seconds (default 30).
  - `WIFI_MONITOR_MIN_DWELL` — minimum seconds to stay on a network after switching (default 180).
  - `WIFI_MONITOR_PING_TARGET` — host used to measure latency for ranking.
  - `WIFI_MONITOR_PING_TIMEOUT` — ping timeout in seconds (default 1).
  - `WIFI_MONITOR_PING_WEIGHT` — divisor used to convert ping latency into a penalty (default 8).
  - `WIFI_MONITOR_AIRPORT_PATH` — override the `airport` scanner path; if the command is missing or fails, the module falls back to CoreWLAN via `swift`.

Config file
- `module.yaml` is the single module manifest/config file. Example keys:
  - `ssids`: array of SSID strings (overridden by `WIFI_MONITOR_SSIDS` env if set)
  - `scan_interval`: seconds between scans
  - `min_dwell`: minimum seconds to stay on a network after switching
  - `ping_target`, `ping_timeout`, `ping_weight`
  - `band_bonus`, `rssi_offset`, `max_ping_penalty` — scoring tuneables

The monitor resolves settings in this order: environment variables (if present) → `module.yaml` → built-in defaults.

6 GHz (6g) support
- The monitor now recognizes 6g networks and gives them a configurable bonus (`band_bonus_6g` in `module.yaml`).

Logs
- Managed by `scriptd` under the shared log directory from `service.yaml`.
