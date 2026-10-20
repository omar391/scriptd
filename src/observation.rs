//! Filesystem observation for the browser bridge.
//!
//! The bridge keeps one shared service snapshot and wakes subscribers when a
//! file that the snapshot depends on changes. Two properties matter here:
//!
//! * Paths must be compared in one canonical form. macOS FSEvents reports the
//!   resolved path (a watch on `/tmp/...` reports `/private/tmp/...`), so a
//!   bridge started from a symlinked path would never match its own events.
//! * Only files that can change the snapshot may wake it, so unrelated
//!   activity in the state directory cannot create refresh loops.

use std::path::{Path, PathBuf};

/// Resolves a path to its canonical form, keeping the original when the path
/// does not exist.
pub fn canonical(path: &Path) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|_| match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => parent
                .canonicalize()
                .map(|parent| parent.join(name))
                .unwrap_or_else(|_| path.to_path_buf()),
            _ => path.to_path_buf(),
        })
}

/// The directories and files the service snapshot depends on.
#[derive(Debug, Clone)]
pub struct WatchScope {
    /// Directory holding runtime state, job queues, and control status files.
    pub state_dir: PathBuf,
    /// Other service-owned runtime directories a detached bridge can observe.
    pub additional_state_dirs: Vec<PathBuf>,
    /// Whether a candidate service state directory is outside this process's watch coverage.
    pub has_unobservable_state_dir: bool,
    /// Repository root that holds `service.yaml` and `modules/`.
    pub repo: PathBuf,
    /// Directory holding the `*.log` and `*.err` files.
    pub log_dir: PathBuf,
}

impl WatchScope {
    /// Builds a scope with every path resolved to its canonical form.
    pub fn new(state_dir: &Path, repo: &Path, log_dir: &Path) -> Self {
        let candidates = [PathBuf::from(
            "/var/root/Library/Application Support/scriptd",
        )];
        let (additional_state_dirs, has_unobservable_state_dir) =
            state_dir_coverage(state_dir, &candidates);
        Self {
            state_dir: canonical(state_dir),
            additional_state_dirs,
            has_unobservable_state_dir,
            repo: canonical(repo),
            log_dir: canonical(log_dir),
        }
    }

    /// Directories to watch, with the recursion each one needs.
    ///
    /// Module configuration lives in `modules/<id>/module.yaml`, so the module
    /// tree is watched recursively while the repository root is not.
    pub fn watch_targets(&self) -> Vec<(PathBuf, bool)> {
        let mut targets = vec![(self.state_dir.clone(), false), (self.repo.clone(), false)];
        targets.extend(
            self.additional_state_dirs
                .iter()
                .cloned()
                .map(|path| (path, false)),
        );
        let modules = self.repo.join("modules");
        if modules.is_dir() {
            targets.push((modules, true));
        }
        if self.log_dir != self.state_dir && self.log_dir != self.repo {
            targets.push((self.log_dir.clone(), false));
        }
        targets
    }

    /// Decides which snapshot inputs a changed path belongs to.
    pub fn classify(&self, path: &Path) -> Relevance {
        let relevance = self.classify_resolved(path);
        if relevance.snapshot || relevance.logs {
            return relevance;
        }
        let resolved = canonical(path);
        if resolved == path {
            relevance
        } else {
            self.classify_resolved(&resolved)
        }
    }

    /// Classifies a path that is already in the same form as the scope.
    fn classify_resolved(&self, path: &Path) -> Relevance {
        Relevance {
            snapshot: self.is_state_input(path) || self.is_config_input(path),
            logs: self.is_log_input(path),
        }
    }

    /// True when the path is a runtime file the snapshot reads.
    fn is_state_input(&self, path: &Path) -> bool {
        if path.parent() != Some(self.state_dir.as_path())
            && !self
                .additional_state_dirs
                .iter()
                .any(|dir| path.parent() == Some(dir.as_path()))
        {
            return false;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            return false;
        };
        if is_atomic_temporary(name) {
            return false;
        }
        name == "state.json"
            || (name.starts_with("jobs-") && name.ends_with(".json"))
            || (name.starts_with("control-") && name.ends_with(".status.json"))
            || name == "mbrew-outcomes.json"
            || (name.starts_with("broker-audit-") && name.ends_with(".json"))
    }

    /// True when the path is a configuration file the snapshot reads.
    fn is_config_input(&self, path: &Path) -> bool {
        if path == self.repo.join("service.yaml") {
            return true;
        }
        let modules = self.repo.join("modules");
        let Ok(relative) = path.strip_prefix(&modules) else {
            return false;
        };
        relative.components().count() == 2
            && relative.file_name().and_then(|value| value.to_str()) == Some("module.yaml")
    }

    /// True when the path is a log file the Logs view reads.
    fn is_log_input(&self, path: &Path) -> bool {
        if path.parent() != Some(self.log_dir.as_path()) {
            return false;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            return false;
        };
        !is_atomic_temporary(name) && (name.ends_with(".log") || name.ends_with(".err"))
    }

    /// True when the path carries inputs the snapshot depends on.
    ///
    /// Only these targets are required: failing to watch one means live
    /// updates are genuinely unreliable. Additional service state directories
    /// are optional, because a process may not be allowed to observe them
    /// while still observing everything that matters.
    pub fn is_required_target(&self, path: &Path) -> bool {
        let resolved = canonical(path);
        resolved == self.state_dir
            || resolved == self.repo
            || resolved == canonical(&self.repo.join("modules"))
            || resolved == self.log_dir
    }
}

/// Selects the extra service state directories this process can observe.
///
/// A service that runs as root keeps its state in `/var/root`, which an
/// unprivileged bridge cannot traverse. Listing that path unconditionally
/// would make one watch registration fail and would report native observation
/// as degraded even though the directories that matter were all watched
/// successfully. A candidate is offered only when it is a readable directory
/// that is not already covered by the primary state directory.
fn observable_state_dirs(state_dir: &Path, candidates: &[PathBuf]) -> Vec<PathBuf> {
    let primary = canonical(state_dir);
    candidates
        .iter()
        .filter(|candidate| std::fs::read_dir(candidate).is_ok())
        .map(|candidate| canonical(candidate))
        .filter(|candidate| *candidate != primary)
        .collect()
}

/// Returns observable state directories and whether a distinct candidate is uncovered.
fn state_dir_coverage(state_dir: &Path, candidates: &[PathBuf]) -> (Vec<PathBuf>, bool) {
    let primary = canonical(state_dir);
    let uncovered = candidates
        .iter()
        .any(|candidate| canonical(candidate) != primary && std::fs::read_dir(candidate).is_err());
    (observable_state_dirs(state_dir, candidates), uncovered)
}

/// Which snapshot inputs a path affects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Relevance {
    /// The path can change the service snapshot.
    pub snapshot: bool,
    /// The path can change the logs shown by the Logs view.
    pub logs: bool,
}

/// True for the temporary files atomic writers create before a rename.
///
/// The rename that follows reports the final path, so the temporary file is
/// ignored and the replacement is classified by its real name.
pub fn is_atomic_temporary(name: &str) -> bool {
    name.ends_with(".tmp")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> (tempfile::TempDir, WatchScope) {
        let root = tempfile::tempdir().expect("temporary root");
        let state = root.path().join("state");
        let repo = root.path().join("repo");
        let logs = root.path().join("logs");
        for path in [&state, &repo.join("modules").join("mcpu"), &logs] {
            std::fs::create_dir_all(path).expect("create directory");
        }
        let scope = WatchScope::new(&state, &repo, &logs);
        (root, scope)
    }

    #[test]
    fn runtime_and_configuration_files_change_the_snapshot() {
        let (_root, scope) = scope();
        for path in [
            scope.state_dir.join("state.json"),
            scope.state_dir.join("jobs-abc123.json"),
            scope.state_dir.join("control-abc123.status.json"),
            scope.repo.join("service.yaml"),
            scope.repo.join("modules").join("mcpu").join("module.yaml"),
        ] {
            assert!(
                scope.classify(&path).snapshot,
                "expected {} to change the snapshot",
                path.display()
            );
        }
        for name in ["mbrew-outcomes.json", "broker-audit-repo.json"] {
            assert!(
                scope.classify(&scope.state_dir.join(name)).snapshot,
                "expected {name} to invalidate the snapshot"
            );
        }
    }

    #[test]
    fn runtime_files_in_an_additional_service_state_directory_are_observed() {
        let (root, mut scope) = scope();
        let service_state = root.path().join("service-state");
        std::fs::create_dir_all(&service_state).expect("create service state directory");
        scope.additional_state_dirs.push(canonical(&service_state));
        assert!(scope
            .watch_targets()
            .iter()
            .any(|(path, _)| path == &canonical(&service_state)));
        assert!(scope.classify(&service_state.join("state.json")).snapshot);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_state_directories_are_not_offered_as_watch_targets() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary root");
        let state = root.path().join("state");
        let unreadable = root.path().join("unreadable-state");
        std::fs::create_dir_all(&state).expect("create state directory");
        std::fs::create_dir_all(&unreadable).expect("create unreadable directory");

        let original_permissions = std::fs::metadata(&unreadable)
            .expect("read candidate permissions")
            .permissions();
        let mut denied_permissions = original_permissions.clone();
        denied_permissions.set_mode(0o000);
        std::fs::set_permissions(&unreadable, denied_permissions)
            .expect("remove candidate permissions");

        // Confirm the fixture really denies directory access before checking
        // that it is excluded. This keeps the regression meaningful when run
        // under a privileged account.
        let access_denied = std::fs::read_dir(&unreadable).is_err();
        let selected = observable_state_dirs(&state, std::slice::from_ref(&unreadable));
        std::fs::set_permissions(&unreadable, original_permissions)
            .expect("restore candidate permissions");

        assert!(access_denied, "fixture must deny directory reads");
        assert!(selected.is_empty(), "unreadable candidate must be excluded");

        // A candidate that does not exist must also be skipped.
        let missing = root.path().join("absent-state");
        assert!(observable_state_dirs(&state, &[missing]).is_empty());
    }

    #[test]
    fn the_primary_state_directory_is_not_repeated_as_an_additional_one() {
        let root = tempfile::tempdir().expect("temporary root");
        let state = root.path().join("state");
        std::fs::create_dir_all(&state).expect("create state directory");

        assert!(observable_state_dirs(&state, std::slice::from_ref(&state)).is_empty());
    }

    #[test]
    fn a_readable_additional_state_directory_is_offered() {
        let root = tempfile::tempdir().expect("temporary root");
        let state = root.path().join("state");
        let service_state = root.path().join("service-state");
        for path in [&state, &service_state] {
            std::fs::create_dir_all(path).expect("create state directory");
        }

        let selected = observable_state_dirs(&state, std::slice::from_ref(&service_state));
        assert_eq!(selected, vec![canonical(&service_state)]);
    }

    #[cfg(unix)]
    #[test]
    fn distinct_unreadable_service_state_keeps_refresh_coverage_without_degrading() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary root");
        let bridge_state = root.path().join("bridge-state");
        let service_state = root.path().join("service-state");
        std::fs::create_dir_all(&bridge_state).expect("create bridge state directory");
        std::fs::create_dir_all(&service_state).expect("create service state directory");
        let original_permissions = std::fs::metadata(&service_state)
            .expect("read service state permissions")
            .permissions();
        let mut denied_permissions = original_permissions.clone();
        denied_permissions.set_mode(0o000);
        std::fs::set_permissions(&service_state, denied_permissions)
            .expect("deny service state access");

        let (selected, uncovered) =
            state_dir_coverage(&bridge_state, std::slice::from_ref(&service_state));
        let access_denied = std::fs::read_dir(&service_state).is_err();
        std::fs::set_permissions(&service_state, original_permissions)
            .expect("restore service state permissions");

        assert!(access_denied, "fixture must deny service state access");
        assert!(selected.is_empty(), "unreadable state must not be watched");
        assert!(
            uncovered,
            "unwatched service state still needs periodic refresh"
        );
    }

    #[test]
    fn the_scope_never_watches_a_state_directory_the_process_cannot_read() {
        // The unprivileged service keeps its state under the user's home, so
        // the root-owned state directory is neither relevant nor readable and
        // must not appear among the watch targets.
        let (_root, scope) = scope();
        assert!(!scope
            .watch_targets()
            .iter()
            .any(|(path, _)| path.starts_with("/var/root")));
    }

    #[test]
    fn only_the_directories_the_snapshot_depends_on_are_required() {
        let (root, mut scope) = scope();
        assert!(scope.is_required_target(&scope.state_dir));
        assert!(scope.is_required_target(&scope.repo));
        assert!(scope.is_required_target(&scope.repo.join("modules")));
        assert!(scope.is_required_target(&scope.log_dir));

        let service_state = root.path().join("service-state");
        std::fs::create_dir_all(&service_state).expect("create service state directory");
        scope.additional_state_dirs.push(canonical(&service_state));
        assert!(
            !scope.is_required_target(&canonical(&service_state)),
            "an optional state directory must not be able to degrade observation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_modules_directory_remains_a_required_watch_target() {
        let root = tempfile::tempdir().expect("temporary root");
        let state = root.path().join("state");
        let repo = root.path().join("repo");
        let logs = root.path().join("logs");
        let actual_modules = root.path().join("actual-modules");
        for path in [&state, &repo, &logs, &actual_modules] {
            std::fs::create_dir_all(path).expect("create directory");
        }
        std::os::unix::fs::symlink(&actual_modules, repo.join("modules"))
            .expect("symlink modules directory");
        let scope = WatchScope::new(&state, &repo, &logs);
        let modules_target = scope.repo.join("modules");

        assert!(scope
            .watch_targets()
            .iter()
            .any(|(path, recursive)| path == &modules_target && *recursive));
        assert!(scope.is_required_target(&modules_target));
        assert!(scope.is_required_target(&canonical(&modules_target)));
    }

    #[test]
    fn unrelated_state_files_do_not_change_the_snapshot() {
        let (_root, scope) = scope();
        for path in [
            scope.state_dir.join("browser-grants.json"),
            scope.state_dir.join("reload-abc.request"),
            scope.state_dir.join("scriptd.lock"),
            scope.state_dir.join("drafts.json"),
        ] {
            assert!(
                !scope.classify(&path).snapshot,
                "expected {} to be ignored",
                path.display()
            );
        }
    }

    #[test]
    fn atomic_temporary_files_are_ignored_but_their_replacement_is_not() {
        let (_root, scope) = scope();
        let temporary = scope.state_dir.join("state.1234-987654321.tmp");
        assert!(!scope.classify(&temporary).snapshot);
        assert!(scope.classify(&scope.state_dir.join("state.json")).snapshot);
    }

    #[test]
    fn only_log_and_error_files_in_the_log_directory_change_the_logs() {
        let (_root, scope) = scope();
        assert!(scope.classify(&scope.log_dir.join("scriptd.log")).logs);
        assert!(scope.classify(&scope.log_dir.join("mcpu.err")).logs);
        assert!(!scope.classify(&scope.log_dir.join("notes.txt")).logs);
        assert!(!scope.classify(&scope.log_dir.join("nested")).logs);
        assert!(!scope.classify(&scope.state_dir.join("scriptd.log")).logs);
    }

    #[test]
    fn only_direct_module_configuration_is_a_snapshot_input() {
        let (_root, scope) = scope();
        assert!(
            !scope
                .classify(
                    &scope
                        .repo
                        .join("modules")
                        .join("mcpu")
                        .join("sub")
                        .join("module.yaml")
                )
                .snapshot
        );
        assert!(
            !scope
                .classify(
                    &scope
                        .repo
                        .join("modules")
                        .join("mcpu")
                        .join("settings.yaml")
                )
                .snapshot
        );
        assert!(!scope.classify(&scope.repo.join("module.yaml")).snapshot);
    }

    #[test]
    fn the_module_tree_is_watched_recursively() {
        let (_root, scope) = scope();
        let modules = scope.repo.join("modules");
        let entry = scope
            .watch_targets()
            .into_iter()
            .find(|(path, _)| path == &modules)
            .expect("module tree is watched");
        assert!(entry.1, "module tree must be watched recursively");
    }

    #[test]
    fn paths_are_compared_in_canonical_form() {
        let root = tempfile::tempdir().expect("temporary root");
        let state = root.path().join("state");
        std::fs::create_dir_all(&state).expect("create state directory");
        let scope = WatchScope::new(&state, root.path(), root.path());
        let resolved = canonical(&state).join("state.json");
        assert!(scope.classify(&resolved).snapshot);
    }
}
