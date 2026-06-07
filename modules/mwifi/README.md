mwifi
===========

This is a small macOS better Wi-Fi selector that filters to known SSIDs, scores each candidate, and switches only when a better choice is worth disrupting the current connection.

It prefers the legacy `airport -s` scan output when available and falls back to a lightweight command-based path when needed.

How ranking works
- If `MWIFI_SSIDS` is set, only those SSIDs are considered.
- If `MWIFI_SSIDS` is empty, the monitor falls back to the system preferred Wi-Fi network list from `networksetup`.
- The order of `ssids` is treated as manual priority. If `ssids` is empty, the system preferred network order is used.
- Each candidate gets a score from band bonus plus RSSI strength (`rssi + 100`, clamped to `0..100`).
- Logs also include `switchScore`, which excludes the current-network sticky bonus and is the score used for switch decisions.
- The current connection is pinged as a health check, not as per-candidate scoring.
- A challenger can win after dwell when its `switchScore` beats the current network by `min_switch_score_delta` points. The default threshold is 10.
- It also respects `MWIFI_MIN_DWELL`, so it will not switch again until the dwell window has passed.
- Joins use the same passwordless `networksetup -setairportnetwork` path as the legacy TypeScript module, then verify that the target SSID became current before writing switch state.
- If passwordless join completes but the target is not observed as current, the monitor can retry `sudo networksetup` with the shared scriptd admin credential, then verifies again.
- If those joins do not actually associate, the monitor can use a Wi-Fi password from `MWIFI_PASSWORD_<SSID>`, `MWIFI_PASSWORD`, or a scriptd-owned Keychain item named `scriptd-mwifi:<SSID>`.
- If the target SSID is saved in the macOS System keychain but has not been provisioned into scriptd yet, the monitor tries to import it on demand. macOS may show a fingerprint/password prompt once; after approval, future runs use the scriptd-owned Keychain item.

Setup
- `./scriptd.sh setup mwifi` imports saved Wi-Fi passwords for configured SSIDs and all currently preferred Wi-Fi networks from macOS.
- Setup may request administrator approval for the System keychain once. It copies each readable AirPort password into a scriptd-owned Keychain item named `scriptd-mwifi:<SSID>`.
- Normal `./scriptd.sh run mwifi` runs use the provisioned scriptd Keychain item or the optional environment password fallback. They only touch the System keychain for an unprovisioned SSID that needs a password-backed join.

Files
- `module.rs` — Rust module implementation.
- `module.yaml` — the single module manifest/config file.

Usage
- `./scriptd.sh run mwifi`
- Enable or disable it from `service.yaml`
- Ongoing cadence is configured in `service.yaml` under `modules.mwifi.schedule`.

Configuration
- Edit `module.yaml` for the default config, or override values through environment variables.
- Useful env vars:
  - `MWIFI_SSIDS` — comma-separated SSIDs to manage.
  - `MWIFI_MIN_DWELL` — minimum seconds to stay on a network after switching (default 180).
  - `MWIFI_PING_TARGET` — host used to check whether the current connection is healthy.
  - `MWIFI_PING_TIMEOUT` — ping timeout in seconds (default 1).
  - `MWIFI_MIN_SWITCH_SCORE_DELTA` — score margin required before switching within the same priority.
  - `MWIFI_PASSWORD_KNIGHT_RIDERS_5G` — optional SSID-specific password fallback; non-alphanumeric SSID characters become `_` and letters are uppercased.
- `MWIFI_AIRPORT_PATH` — override the `airport` scanner path; if the command is missing or fails, the module uses a safer command-based fallback.

Config file
- `module.yaml` is the single module manifest/config file. Example keys:
  - `ssids`: array of SSID strings (overridden by `MWIFI_SSIDS` env if set)
  - `min_dwell`: minimum seconds to stay on a network after switching
  - `ping_target`, `ping_timeout`
  - `band_bonus_2g`, `band_bonus_5g`, `band_bonus_6g`, `rssi_offset`, `min_switch_score_delta`

The monitor resolves settings in this order: environment variables (if present) → `module.yaml` → built-in defaults.

6 GHz (6g) support
- The monitor now recognizes 6g networks and gives them a configurable bonus (`band_bonus_6g` in `module.yaml`).

Logs
- Managed by `scriptd` under the shared log directory from `service.yaml`.
