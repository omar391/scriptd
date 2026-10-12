use super::*;
use std::time::Instant;

fn ui_owner() -> UiOwner {
    UiOwner {
        request_id: "d".repeat(64),
        identity: process::UiHelperIdentity {
            pid: 123,
            pid_version: 9,
            start_seconds: 1_700_000_000,
            start_microseconds: 123_456,
            user_id: 501,
            executable: "/usr/bin/swift".to_string(),
        },
        last_heartbeat_unix_millis: 10_000,
    }
}

fn candidate(pid: u32, fingerprint: &str) -> Candidate {
    Candidate {
        identity: ProcessIdentity {
            pid,
            pid_version: 10,
            start_seconds: 1_700_000_000,
            start_microseconds: 123_456,
            executable: "/opt/tools/trunk".to_string(),
            user_id: 501,
            fingerprint: fingerprint.to_string(),
            code_directory_hash: "c".repeat(40),
        },
        name: "trunk".to_string(),
        cpu_percent: 82.0,
        memory_bytes: 4096,
        reason: "detached CLI".to_string(),
    }
}

#[test]
fn approved_timer_boundary_requires_full_observed_duration() {
    let now = Instant::now();
    let candidate = candidate(42, &"a".repeat(64));
    let track = TrackedProcess {
        identity: candidate.identity.clone(),
        first_high_at: now - Duration::from_secs(1_799),
        last_sample_at: now,
    };
    assert_eq!(
        cleanup_action(Some(&track), None, Duration::from_secs(1_800), now),
        None
    );
    let mature = TrackedProcess {
        first_high_at: now - Duration::from_secs(1_800),
        ..track.clone()
    };
    assert_eq!(
        cleanup_action(Some(&mature), None, Duration::from_secs(1_800), now),
        Some(CleanupAction::Terminate)
    );
}

#[test]
fn escalation_waits_at_least_sixty_seconds() {
    let now = Instant::now();
    let candidate = candidate(42, &"a".repeat(64));
    let track = TrackedProcess {
        identity: candidate.identity.clone(),
        first_high_at: now - Duration::from_secs(1_900),
        last_sample_at: now,
    };
    let escalation = Escalation {
        identity: candidate.identity.clone(),
        term_sent_at: now - Duration::from_secs(59),
    };
    assert_eq!(
        cleanup_action(
            Some(&track),
            Some(&escalation),
            Duration::from_secs(1_800),
            now
        ),
        None
    );
    let ready = Escalation {
        term_sent_at: now - TERM_GRACE_PERIOD,
        ..escalation
    };
    assert_eq!(
        cleanup_action(Some(&track), Some(&ready), Duration::from_secs(1_800), now),
        Some(CleanupAction::Kill)
    );
}

#[test]
fn missed_samples_and_pid_reuse_restart_timing() {
    let now = Instant::now();
    let first = candidate(42, &"a".repeat(64));
    let mut tracked = HashMap::new();
    assert_eq!(observe_candidate(&mut tracked, &first, now), Duration::ZERO);
    let reused = candidate(42, &"b".repeat(64));
    assert_eq!(
        observe_candidate(&mut tracked, &reused, now + Duration::from_secs(60)),
        Duration::ZERO
    );
    assert_eq!(
        observe_candidate(&mut tracked, &reused, now + Duration::from_secs(151)),
        Duration::ZERO
    );
}

#[test]
fn missing_or_recovered_processes_drop_tracking_and_escalation() {
    let now = Instant::now();
    let candidate = candidate(42, &"a".repeat(64));
    let mut tracked = HashMap::from([(
        42,
        TrackedProcess {
            identity: candidate.identity.clone(),
            first_high_at: now - Duration::from_secs(500),
            last_sample_at: now,
        },
    )]);
    let mut escalations = HashMap::from([(
        42,
        Escalation {
            identity: candidate.identity,
            term_sent_at: now - Duration::from_secs(90),
        },
    )]);
    reconcile_tracking(&mut tracked, &HashMap::new());
    reconcile_escalations(&mut escalations, &HashMap::new());
    assert!(tracked.is_empty());
    assert!(escalations.is_empty());
}

#[test]
fn changed_start_time_executable_or_user_is_a_different_process() {
    let now = Instant::now();
    let original = candidate(42, &"a".repeat(64));
    let mut tracked = HashMap::new();
    let _ = observe_candidate(&mut tracked, &original, now);
    let mut replacement = candidate(42, &"a".repeat(64));
    replacement.identity.start_seconds += 1;
    assert_eq!(
        observe_candidate(&mut tracked, &replacement, now + Duration::from_secs(60)),
        Duration::ZERO
    );
}

#[test]
fn heartbeat_freshness_tracks_health_without_deciding_response_deadlines() {
    let heartbeat = UiHeartbeat {
        request_id: "d".repeat(64),
        pid: 123,
        unix_millis: 10_000,
    };
    assert!(heartbeat_is_fresh(&heartbeat, 39_999));
    assert!(!heartbeat_is_fresh(&heartbeat, 40_000));
    assert!(heartbeat_is_fresh(&heartbeat, 9_999));
    assert!(heartbeat_matches_owner(&heartbeat, &ui_owner()));
}

#[test]
fn refreshing_an_unanswered_dialog_heartbeat_keeps_it_alive_past_sixty_seconds() {
    let mut heartbeat = UiHeartbeat {
        request_id: "d".repeat(64),
        pid: 123,
        unix_millis: 10_000,
    };
    for elapsed in (0..=120_000).step_by(5_000) {
        heartbeat.unix_millis = 10_000 + elapsed;
        assert!(heartbeat_is_fresh(
            &heartbeat,
            heartbeat.unix_millis + 1_000
        ));
    }
}

#[test]
fn a_stale_heartbeat_for_a_different_pid_cannot_replace_the_ui_owner() {
    let mut heartbeat = UiHeartbeat {
        request_id: "d".repeat(64),
        pid: 124,
        unix_millis: 1,
    };
    let owner = ui_owner();
    assert!(!heartbeat_matches_owner(&heartbeat, &owner));
    heartbeat.pid = owner.identity.pid;
    heartbeat.request_id = "e".repeat(64);
    assert!(!heartbeat_matches_owner(&heartbeat, &owner));
}

#[test]
fn cleanup_signal_adapter_is_never_called_after_a_failed_identity_check() {
    let candidate = candidate(42, &"a".repeat(64));
    let sent = std::cell::Cell::new(false);
    let result = send_signal_with(
        &candidate,
        libc::SIGTERM,
        |_| anyhow::bail!("protected process"),
        |_, _| {
            sent.set(true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!sent.get());
}

#[test]
fn cleanup_signal_is_withheld_when_loaded_policy_cannot_be_persisted() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let policy_root = temp.path().join("mcpu");
    let store = PolicyStore::new(policy_root.clone());
    let lock = store.lock().expect("policy lock");
    let candidate = candidate(42, &"a".repeat(64));
    let mut policy = PolicyFile::default();
    policy.approvals.insert(
        candidate.identity.executable.clone(),
        policy::Approval {
            canonical_path: candidate.identity.executable.clone(),
            fingerprint: candidate.identity.fingerprint.clone(),
            timer_minutes: policy::DEFAULT_TIMER_MINUTES,
        },
    );
    lock.save(&policy).expect("persist readable approval");
    let loaded = lock.load().expect("load approval before storage failure");

    let policy_path = policy_root.join("policy.json");
    std::fs::remove_file(&policy_path).expect("remove policy file after loading");
    std::fs::create_dir(&policy_path).expect("make policy replacement unwritable");

    let signaled = std::cell::Cell::new(false);
    let result = send_signal_with_policy_persistence(
        &candidate,
        libc::SIGTERM,
        || lock.save(&loaded),
        |_| Ok(()),
        |_, _| {
            signaled.set(true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(
        !signaled.get(),
        "an unpersistable approval must send no signal"
    );
}

#[test]
fn cleanup_signal_adapter_targets_one_pid_only() {
    let candidate = candidate(42, &"a".repeat(64));
    let sent = std::cell::Cell::new(None);
    send_signal_with(
        &candidate,
        libc::SIGTERM,
        |_| Ok(()),
        |identity, signal| {
            sent.set(Some((identity.pid, identity.pid_version, signal)));
            Ok(())
        },
    )
    .expect("verified individual process signal");
    assert_eq!(sent.get(), Some((42, 10, libc::SIGTERM)));
}

#[test]
fn unresponsive_ui_recovery_targets_its_verified_process_generation() {
    let owner = ui_owner();
    let sent = std::cell::Cell::new(None);
    stop_ui_helper_with(&owner, |pid, pid_version, signal| {
        sent.set(Some((pid, pid_version, signal)));
        Ok(())
    })
    .expect("stop the verified unresponsive UI helper");
    assert_eq!(
        sent.get(),
        Some((
            owner.identity.pid,
            owner.identity.pid_version,
            libc::SIGKILL
        ))
    );
}

#[test]
fn rejected_response_is_removed_before_rejection_acknowledgement() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    let candidate = candidate(42, &"a".repeat(64));
    let request = policy::new_pending(&candidate, "2026-10-13T00:00:00Z".to_string())
        .expect("create isolated request");
    let mut policy = PolicyFile::default();
    policy
        .pending
        .insert(request.request_id.clone(), request.clone());
    store
        .prepare_response_directory()
        .expect("response directory");
    std::fs::write(
        store.response_path(&request.request_id),
        b"invalid response",
    )
    .expect("write rejected response");

    reject_pending_response(&store, &policy, &request.request_id, "invalid choice")
        .expect("reject response");
    assert!(!store.response_path(&request.request_id).exists());
    let acknowledgement: policy::UiAcknowledgement = serde_json::from_slice(
        &std::fs::read(store.acknowledgement_path(&request.request_id))
            .expect("read acknowledgement bytes"),
    )
    .expect("decode rejection acknowledgement");
    assert!(!acknowledgement.accepted);

    // A resubmission after observing the rejection must survive supervisor cleanup.
    std::fs::write(
        store.response_path(&request.request_id),
        b"corrected choice",
    )
    .expect("write corrected response");
    assert!(store.response_path(&request.request_id).exists());
}

#[test]
fn failed_policy_read_resets_tracking_escalation_and_sampler_baseline() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let module_dir = temp.path().join("modules/mcpu");
    let log_dir = temp.path().join("logs");
    std::fs::create_dir_all(&module_dir).expect("module directory");
    std::fs::create_dir_all(&log_dir).expect("log directory");
    let mut context = crate::modules::module_context_with_settings(
        "mcpu",
        temp.path().to_path_buf(),
        module_dir,
        log_dir,
        false,
        crate::config::ModuleSettings::Mcpu(McpuConfig {
            cpu_threshold: 50,
            exclude_apps: Vec::new(),
        }),
    );
    let policy_root = temp.path().join("isolated-support/mcpu");
    let store = PolicyStore::new(policy_root.clone());
    {
        let lock = store.lock().expect("create private policy directory");
        lock.save(&PolicyFile::default())
            .expect("save valid policy");
    }
    std::fs::write(policy_root.join("policy.json"), b"{corrupt").expect("corrupt isolated policy");

    let now = Instant::now();
    let candidate = candidate(42, &"a".repeat(64));
    let mut state = McpuState::default();
    state.tracked.insert(
        candidate.identity.pid,
        TrackedProcess {
            identity: candidate.identity.clone(),
            first_high_at: now - Duration::from_secs(2_000),
            last_sample_at: now,
        },
    );
    state.escalations.insert(
        candidate.identity.pid,
        Escalation {
            identity: candidate.identity,
            term_sent_at: now - Duration::from_secs(90),
        },
    );
    let _ = state.sampler.sample(&[], 50.0);

    assert!(run_once_with_state(&mut context, &mut state, &store).is_err());
    assert!(state.tracked.is_empty());
    assert!(state.escalations.is_empty());
    assert!(state.policy_digest.is_none());
    assert!(state.last_error.is_some());
    assert!(
        !state.sampler.sample(&[], 50.0).warmed,
        "a failed scan must invalidate the CPU sampler baseline"
    );
}

#[test]
fn isolated_module_entrypoint_keeps_production_policy_and_processes_untouched() {
    let temp = tempfile::tempdir().expect("isolated module workspace");
    let module_dir = temp.path().join("modules/mcpu");
    let log_dir = temp.path().join("logs");
    std::fs::create_dir_all(&module_dir).expect("module directory");
    std::fs::create_dir_all(&log_dir).expect("log directory");
    let mut context = crate::modules::module_context_with_settings(
        "mcpu",
        temp.path().to_path_buf(),
        module_dir,
        log_dir,
        false,
        crate::config::ModuleSettings::Mcpu(McpuConfig {
            cpu_threshold: 50,
            exclude_apps: Vec::new(),
        }),
    );
    let policy_root = temp.path().join("isolated-support/mcpu");
    let store = PolicyStore::new(policy_root.clone());
    let mut state = McpuState::default();

    for _ in 0..2 {
        let status = run_once_with_state(&mut context, &mut state, &store)
            .expect("isolated mcpu scan")
            .expect("module status");
        let metrics = status.metrics.expect("metrics");
        assert_eq!(metrics["pending_enrollment"], 0);
        assert_eq!(metrics["last_term_pid"], "none");
        assert_eq!(metrics["last_killed_pid"], "none");
    }

    assert!(!policy_root.join("policy.json").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn isolated_module_protects_a_live_high_cpu_cli_child() {
    use std::io::Write;
    use std::process::Stdio;

    let temp = tempfile::tempdir().expect("isolated module workspace");
    let source = temp.path().join("active-cli-load.c");
    let executable = temp.path().join("active-cli-load");
    let mut source_file = std::fs::File::create(&source).expect("create synthetic CLI source");
    source_file
        .write_all(
            b"#include <stdint.h>\nint main(void) { volatile uint64_t n = 0; for (;;) { n++; } }\n",
        )
        .expect("write synthetic CLI source");
    let compile = Command::new("/usr/bin/clang")
        .arg("-O2")
        .arg("-o")
        .arg(&executable)
        .arg(&source)
        .output()
        .expect("compile isolated synthetic CLI");
    assert!(
        compile.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let mut child = Command::new(&executable)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start active synthetic CLI child");
    let result = (|| -> anyhow::Result<()> {
        let module_dir = temp.path().join("modules/mcpu");
        let log_dir = temp.path().join("logs");
        std::fs::create_dir_all(&module_dir)?;
        std::fs::create_dir_all(&log_dir)?;
        let mut context = crate::modules::module_context_with_settings(
            "mcpu",
            temp.path().to_path_buf(),
            module_dir,
            log_dir,
            false,
            crate::config::ModuleSettings::Mcpu(McpuConfig {
                cpu_threshold: 50,
                exclude_apps: Vec::new(),
            }),
        );
        let policy_root = temp.path().join("isolated-support/mcpu");
        let store = PolicyStore::new(policy_root.clone());
        let mut state = McpuState::default();

        let _ = run_once_with_state(&mut context, &mut state, &store)?;
        std::thread::sleep(Duration::from_secs(2));
        let status = run_once_with_state(&mut context, &mut state, &store)?
            .context("isolated mcpu status")?;
        let metrics = status.metrics.context("isolated mcpu metrics")?;
        anyhow::ensure!(
            metrics["protected_high_cpu"].as_u64().unwrap_or_default() > 0,
            "live high-CPU process was not reported as protected"
        );
        anyhow::ensure!(
            metrics["pending_enrollment"].as_u64() == Some(0),
            "active child workload must not create an enrollment request"
        );
        anyhow::ensure!(
            metrics["last_term_pid"].as_str() == Some("none")
                && metrics["last_killed_pid"].as_str() == Some("none"),
            "active child workload must not receive cleanup signals"
        );
        anyhow::ensure!(
            !policy_root.join("policy.json").exists(),
            "isolated scan must not persist production or cleanup policy"
        );
        Ok(())
    })();

    if child
        .try_wait()
        .expect("inspect synthetic CLI child")
        .is_none()
    {
        child.kill().expect("stop synthetic CLI child");
        child.wait().expect("reap synthetic CLI child");
    }
    result.expect("protect live high-CPU CLI child");
}
