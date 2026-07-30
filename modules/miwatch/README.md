miwatch
==============

`miwatch` executes the authenticated remote reboot action for a typed global
trigger incident. The supervisor owns Wi-Fi/network sampling, the
05:00-inclusive–02:00-exclusive window, Boolean evaluation, sustained-match
debounce, latch, and recovery reset.

Safety state
------------

- The module is disabled by default in `service.yaml`.
- It fails closed unless `verified_remote_api: true` and a complete request
  profile have been populated from authorized Mi WiFi APK plus authenticated
  device evidence.
- A transport timeout or connection loss after a reboot request is treated as
  ambiguous and is never retried during the same outage.
- Trigger incidents and action attempt/cooldown state are persisted atomically
  across process restarts.
- `attempt_started` is persisted before sending the HTTP request. A crash,
  timeout, or connection loss cannot redispatch that incident.
- Logs contain incident/outcome summaries only; tokens, cookies,
  request bodies, and response bodies are not logged.

LAN and recovery limits
-----------------------

The trigger is local SSID visibility, not Internet reachability: the watchdog
does not ping a public target before rebooting. If the Mac has Ethernet,
another Wi-Fi path, or another working route, the cloud reboot request can be
independent of the missing router LAN. If `knight_riders_5G` is the Mac's only
route, the reboot request will normally fail or become ambiguous; the client
records that outcome and suppresses retries for the outage. A missing SSID can
also represent a Mac radio/driver problem rather than a router failure, so a
live LAN-independence test is required before enabling production automation.

Configuration
-------------

Edit `modules.miwatch.triggers.outage` in
[`service.yaml`](../../service.yaml) for the SSID, timezone/window, schedule,
network-throughput threshold, match debounce, and reset debounce. `module.yaml` retains only
action concerns: cooldown, state/session paths, the verified remote profile,
and request timeout. Complex trigger changes are YAML-authored; the CLI only
changes module enablement.

`process_network.at_least_bytes_per_second` is checked against a one-second
external-interface delta sample at each scheduled observation. The configured
three matches over at least 60 seconds mean three qualifying samples, not a
continuous 60-second average. Missing a required 30-second schedule pulse
breaks the match streak. The recovery latch uses SSID visibility alone for two
observations over at least 30 seconds; the Mac does not need to reassociate
with that SSID before the outage can rearm.

The session file is a scriptd-owned JSON file. The one-time emulator bootstrap
must provision `user_id` or `c_user_id` and `pass_token`; the file may also
contain the current `service_token`, Base64 `ssecurity`, optional
`time_diff_ms`, `expires_at`, the router's private target ID, and a cookie map.
Never commit this file, put credentials or device identifiers in
`module.yaml`, pass tokens in command-line arguments, or log the file contents.
scriptd writes it atomically with mode `0600`.

After bootstrap, scriptd refreshes the Xiaomi service credential directly:

1. `GET https://account.xiaomi.com/pass/serviceLogin` with the account cookies,
   the regional router service ID, and `_json=true`;
2. compute the APK-compatible `clientSign` from the returned `nonce` and
   `ssecurity`, then `GET` the returned location with
   `_userIdNeedEncrypt=true`; and
3. store the returned `serviceToken` cookie and a 24-hour expiry, then use it
   for the signed reboot request.

Use the explicit refresh command after the emulator bootstrap and whenever a
session is being repaired:

```bash
cat /secure/bootstrap.json | ./scriptd.sh miwatch session import
./scriptd.sh miwatch session refresh
```

`session import` reads JSON only from standard input, validates the required
account fields, and writes the configured session store with mode `0600`.

The watchdog also refreshes automatically before an expired request and once
after an HTTP 401. If the pass-token bootstrap fields are unavailable, it
fails closed and asks for the authorized emulator bootstrap again. Passwords
are never stored or sent by scriptd.

The minimum one-time seed is shaped like this; replace placeholders only in
the local `token_file`:

```json
{
  "access_token": "",
  "user_id": "<xiaomi-user-id>",
  "c_user_id": "<optional-encrypted-user-id>",
  "pass_token": "<account-pass-token>",
  "router_private_id": "<router-private-id-from-the-authorized-app>",
  "service_token": "<optional-current-service-token>",
  "ssecurity": "<optional-base64-ssecurity>",
  "expires_at": 0,
  "cookies": {}
}
```

The authorized emulator is used only to complete that initial Xiaomi login
and collect those account fields through the repository collector. It reads
the APK's authenticated `MiAccountManager` API, not private app files, and
streams the JSON over stdin into scriptd. Do not use `adb logcat` as a token
transport.

When `miwatch` needs to issue a reboot and the session file is missing, lacks
bootstrap fields, or cannot refresh, the Rust reboot path automatically
compiles and runs the collector, imports the account fields, performs the
direct service-token refresh, and continues with the reboot. It requires the
logged-in, debuggable `codex_mygp`-style AVD because the collector uses
`adb root` to load the authorized APK's own account-manager classes.

Verified request profile
------------------------

The authorized [Mi Wi-Fi 5.9.0 APKMirror artifact](https://www.apkmirror.com/apk/xiaomi-inc/mi-wi-fi/mi-wi-fi-5-9-0-release/mi-wi-fi-5-9-0-2-android-apk-download/)
supplied static evidence for the remote branch:

- package `com.xiaomi.router`, version `5.9.0` / version code `50900`;
- capability `remote_reboot` selects `POST /s/diagnosis/control/reboot` with
  `REMOTE_ONLY` policy and the router private ID;
- the default CN service is `xiaoqiang` at `https://api.miwifi.com`; the APK
  also contains the EU and IN API bases and service IDs;
- the app builds an empty application payload, then adds Xiaomi's signed
  form fields (`deviceID`, `deviceId`, `routerID`, `rc4_hash__`, `signature`,
  and `_nonce`), using the service credential's `ssecurity` and minute-level
  clock offset; and
- the request uses the app's Xiaomi cookie jar and advertises
  `MiWiFi-Supported-Compression: deflate`; its User-Agent is the Android
  `http.agent` value followed by `APP/com.xiaomi.router APPV/5.9.0`.

The authenticated emulator session and authorized R2100 router target were
then verified through the app's own debug screen. Device serial and target
identifier values are intentionally omitted from documentation. The remote API
requires the same account cookie set that the APK's `LoginManager` attaches:
`serviceToken`, `userId`, `cUserId`, and `passToken`. `miwatch` supplies those
restricted session values only to the Xiaomi API; it never logs them.

On 2026-07-30, one explicitly approved live cloud reboot was accepted by the
Xiaomi API. The Mac's Wi-Fi association dropped, `knight_riders_5G` became
visible again, and the authenticated read-only preflight recovered with HTTP
200. The attempt and cooldown were persisted before the request, and the state
store was verified as mode `0600`. Production automation was then enabled.

The legacy generic template path remains test-only and must not be used for
Xiaomi. The code contains the APK's RC4-drop-1024/SHA-256/SHA-1 signing path,
the direct pass-token refresh exchange, and local mock capture tests.

Usage
-----

```bash
./scriptd.sh config miwatch --enable
./scriptd.sh miwatch remote verify
./scriptd.sh run miwatch
```

`remote verify` is read-only and checks the authenticated Xiaomi route without
issuing a reboot. `run miwatch` is a manual reboot attempt: it bypasses global
conditions but still enforces the exact verified profile, cooldown,
attempt-before-request persistence, and no retry after an ambiguous result.
