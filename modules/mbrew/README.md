mbrew
============

This module runs Homebrew maintenance under `scriptd`.

Cask safety
- Scheduled and manual runs use the same non-interrupting policy.
- Outdated casks are upgraded one at a time only after `mbrew` confirms that
  their application and helpers are not running.
- Casks with an active process, missing/ambiguous runtime metadata, or an
  unavailable running-app query are deferred and retried on the next run.
- Failed upgrades are reported for retry; `mbrew` does not force, uninstall, or
  reinstall casks automatically.

Trust policy
- `settings.trusted_taps` is an explicit allowlist for third-party taps.
- Before `brew update`, `mbrew` runs `brew trust --tap` only for allowlisted taps
  that are currently installed.
- If Homebrew still reports an untrusted entry, the run fails and names it; new
  taps are never trusted implicitly.
- Whole-tap trust permits current and future formulae, casks, and commands from
  that tap, so only list taps that have been reviewed and approved.

Files
- `module.rs` — Rust plugin implementation.
- `module.yaml` — the single module manifest/config file.

Usage
- `./scriptd.sh config mbrew`
- `./scriptd.sh run mbrew`
- enable or disable it from `service.yaml`

Security
- Setup stores one durable admin credential in the current user's login Keychain as `scriptd:ScriptdAdmin`; `mbrew` and `mwifi` share it.
- The askpass script no longer reads or prints the stored password. Brew maintenance should rely on the sudoers rules installed during setup.
