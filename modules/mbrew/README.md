mbrew
============

This module runs Homebrew maintenance under `scriptd`.

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
