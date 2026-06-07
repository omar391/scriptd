brew-manager
============

This module runs Homebrew maintenance under `scriptd`.

Files
- `module.rs` — Rust plugin implementation.
- `module.yaml` — the single module manifest/config file.

Usage
- `./scriptd.sh setup brew-manager`
- `./scriptd.sh run brew-manager`
- enable or disable it from `service.yaml`

Security
- Setup stores the durable admin credential through the shared scriptd Keychain helper as `ScriptdAdmin`.
- The askpass script no longer reads or prints the stored password. Brew maintenance should rely on the sudoers rules installed during setup.
