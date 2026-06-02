wifi-monitor
===========

This is a small macOS Wi-Fi monitor that filters to known SSIDs, scores each candidate, and switches only when a better choice is worth disrupting the current connection.

It prefers the legacy `airport -s` scan output when available and falls back to a lightweight command-based path when needed.

How ranking works
- If `WIFI_MONITOR_SSIDS` is set, only those SSIDs are considered.
- If `WIFI_MONITOR_SSIDS` is empty, the monitor falls back to the system preferred Wi-Fi network list from `networksetup`.
- The order of `ssids` is treated as manual priority. If `ssids` is empty, the system preferred network order is used.
- Each candidate gets a score from band bonus plus RSSI strength (`rssi + 100`, clamped to `0..100`).
- The current connection is pinged as a health check, not as per-candidate scoring.
- A higher-priority SSID can win after dwell. Within the same priority, a challenger must beat the current score by `min_switch_score_delta`.
- It also respects `WIFI_MONITOR_MIN_DWELL`, so it will not switch again until the dwell window has passed.

Files
- `module.rs` — Rust module implementation.
- `module.yaml` — the single module manifest/config file.

Usage
- `./scriptd.sh run wifi-monitor`
- Enable or disable it from `service.yaml`
- Ongoing cadence is configured in `service.yaml` under `modules.wifi-monitor.schedule`.

Configuration
- Edit `module.yaml` for the default config, or override values through environment variables.
- Useful env vars:
  - `WIFI_MONITOR_SSIDS` — comma-separated SSIDs to manage.
  - `WIFI_MONITOR_MIN_DWELL` — minimum seconds to stay on a network after switching (default 180).
  - `WIFI_MONITOR_PING_TARGET` — host used to check whether the current connection is healthy.
  - `WIFI_MONITOR_PING_TIMEOUT` — ping timeout in seconds (default 1).
  - `WIFI_MONITOR_MIN_SWITCH_SCORE_DELTA` — score margin required before switching within the same priority.
- `WIFI_MONITOR_AIRPORT_PATH` — override the `airport` scanner path; if the command is missing or fails, the module uses a safer command-based fallback.

Config file
- `module.yaml` is the single module manifest/config file. Example keys:
  - `ssids`: array of SSID strings (overridden by `WIFI_MONITOR_SSIDS` env if set)
  - `min_dwell`: minimum seconds to stay on a network after switching
  - `ping_target`, `ping_timeout`
  - `band_bonus_2g`, `band_bonus_5g`, `band_bonus_6g`, `rssi_offset`, `min_switch_score_delta`

The monitor resolves settings in this order: environment variables (if present) → `module.yaml` → built-in defaults.

6 GHz (6g) support
- The monitor now recognizes 6g networks and gives them a configurable bonus (`band_bonus_6g` in `module.yaml`).

Logs
- Managed by `scriptd` under the shared log directory from `service.yaml`.
