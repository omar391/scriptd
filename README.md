# Scriptd Automation Bridge

This public repository contains the small privileged companion used by the Scriptd macOS app. The app owns automation rules, schedules, policies, configuration, and the user interface. The bridge accepts only typed, paired requests for operations that require privileges unavailable to the sandboxed app; it does not evaluate schedules or run Homebrew maintenance.

Homebrew remains responsible for package maintenance. The Scriptd app configures Homebrew's own supported behavior and presents its status.

## Bridge scope

The bridge authenticates the paired app's signed identity, reports available capabilities, accepts narrowly typed operations, records durable operation receipts, supports revocation, and avoids replaying uncertain work after restart. The current protocol exposes only the minimal privileged operation implemented by this release. Missing capabilities are reported as unavailable.

The bridge is installed separately from the Mac App Store app and runs as a root-owned LaunchDaemon. Its package is signed and notarized in release automation. Installation and pairing require explicit macOS administrator approval. Before the app can pair, an administrator grants one pairing for the exact signing team and bundle identifier with `sudo /usr/local/libexec/scriptd-bridge authorize-pairing TEAM_IDENTIFIER BUNDLE_IDENTIFIER`. The bridge consumes that protected approval on successful pairing; revoking a pairing requires a new administrator approval before it can be activated again.

## Build and test

Requires Rust stable and macOS:

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --release -p scriptd-bridge
```

The `scriptd-bridge-protocol` crate defines the versioned wire types shared with the private desktop app. Release artifacts are built from this public repository alone.

## Tracked helper source

`assets/mbrew/brew_askpass.sh` is retained as a tracked source asset for compatibility with existing installs. Homebrew maintenance itself is performed by Homebrew; the desktop app configures Homebrew and does not use this helper to run upgrades.

## License

The bridge and protocol are available under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
