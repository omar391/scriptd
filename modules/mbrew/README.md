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
