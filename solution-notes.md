# Solution Notes

Goal: Reverse-engineer the authorized Mi WiFi Android app's authenticated remote router-reboot operation and add, test, and document a scriptd watchdog for the `knight_riders_5G` outage window.

Store only verified, reusable lessons from this goal's execution. Keep entries concise and use this shape:

## Entry Format

### Concise issue signature

- Symptoms: `observable failure`
- Preconditions: `context in which the fix applies`
- Cause: `verified or evidence-backed cause`
- Fix: `smallest reliable correction`
- Verification: `evidence that the fix worked`
- Limits: `contexts where the fix does not apply`

## Entries

### Xiaomi Mi WiFi signing delimiter

- Symptoms: a static reimplementation produced valid-looking but different signatures from the APK runtime.
- Preconditions: reproducing `com.xiaomi.router` 5.9.0 `n3.d.ServerCallModifier` signatures.
- Cause: `CloudCoder.b()` joins method, encoded path, sorted parameters, and security with Kotlin `Typography.amp` (`&`), not a newline.
- Fix: execute the APK builder in Android `app_process64`, compare a captured nonce vector, and use the exact `&` delimiter in scriptd.
- Verification: dynamic APK output, actual APK/OkHttp loopback wire capture, the independent Rust/Python vector, and the direct pass-token refresh mock match the observed protocol; the full Rust suite passes.
- Limits: this validates request construction and refresh sequencing with synthetic credentials; it does not validate a live authenticated router response.

### Xiaomi service-token refresh after one-time emulator bootstrap

- Symptoms: forcing an emulator login for every watchdog run is slow and leaves the automation dependent on Android UI state.
- Preconditions: the authorized emulator has completed Xiaomi login once and the local session store contains `user_id` or `c_user_id` plus `pass_token`.
- Cause: the APK exposes a direct `serviceLogin` → `clientSign` exchange using the account pass token; the Android `AccountManager` path is only needed to obtain the initial account credential.
- Fix: persist the bootstrap fields in the `0600` miwatch session store, call `scriptd.sh miwatch session refresh`, and refresh automatically on expiry or one HTTP 401 before retrying once.
- Verification: the local mock test observes the account login request, service-token exchange, and signed reboot request in that order, with the refreshed cookie used on reboot.
- Limits: this does not scrape private APK storage or bypass Xiaomi login; an expired/revoked pass token still requires the authorized emulator bootstrap again.

### Autonomous emulator session collection belongs in the Rust module

- Symptoms: a shell wrapper can collect tokens, but it leaves the security-sensitive orchestration outside scriptd.
- Preconditions: a logged-in adb-root Android AVD with the authorized Mi Wi-Fi APK installed.
- Cause: the Xiaomi account manager is exposed inside the APK process classloader, while the host must own import, permissions, and refresh sequencing.
- Fix: the Rust reboot path now compiles/runs the small APK API collector when its session is absent or unusable, streams its JSON directly into the Rust session store, and performs the direct refresh without shell arguments or token logs.
- Verification: the Rust session path completed collection and refresh against the logged-in authorized AVD; the resulting restricted session store contains service credentials and is mode `0600`.
- Limits: collection requires an adb-root emulator; it does not work against a locked production device or an emulator that has not completed Xiaomi login.

### Xiaomi API session needs the APK account-cookie set

- Symptoms: an APK-compatible signed remote request was rejected even though the service token and request signatures were valid.
- Preconditions: an authenticated Mi Wi-Fi account session and a router profile obtained from the app's DebugInfoActivity.
- Cause: the APK's `LoginManager` puts `serviceToken`, `userId`, `cUserId`, and `passToken` in the API-host cookie jar; scriptd had sent only `serviceToken`.
- Fix: attach the same restricted account-cookie set, add a read-only authenticated `init_info` preflight, and collect an emulator-issued service token when available.
- Verification: preflight returned HTTP 200; the approved three-tick Rust watchdog run sent one remote reboot request at threshold 3, Xiaomi accepted it, state recorded `last_outcome=reboot_accepted`, and preflight again returned HTTP 200 after the reboot interval.
- Limits: acceptance and subsequent API availability prove the live cloud operation for this exact account/router profile; the module remains disabled by default and still treats a missing SSID as a potentially local Mac fault.

### Codex desktop traffic can be hosted by ChatGPT.app

- Symptoms: `process_network: applications: [Codex]` observed no traffic even while Codex subprocesses were transferring data.
- Preconditions: a Codex desktop build whose service and CLI components live inside the signed `ChatGPT.app` bundle instead of an outer `Codex.app` bundle.
- Cause: outer-bundle-only attribution correctly identified `ChatGPT`, but lost the narrower Codex component identity.
- Fix: retain outer-bundle attribution and add the logical `Codex` owner only for exact Codex app components or the bundled `Contents/Resources/codex` executable under `ChatGPT.app`; loose process-name matches remain excluded.
- Verification: a live read-only `nettop` delta showed Codex traffic, executable-path inspection confirmed the two trusted ChatGPT-owned locations, and synthetic aggregation tests cover both host layouts.
- Limits: unknown loose `codex` executables outside a recognized app bundle intentionally do not count.
