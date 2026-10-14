use super::*;

fn test_request() -> PendingRequest {
    PendingRequest {
        request_id: "a".repeat(64),
        identity: ProcessIdentity {
            pid: 42,
            pid_version: 10,
            start_seconds: 1_700_000_000,
            start_microseconds: 123_456,
            executable: "/opt/tools/trunk".to_string(),
            user_id: 501,
            fingerprint: "b".repeat(64),
            code_directory_hash: "c".repeat(40),
        },
        name: "trunk".to_string(),
        cpu_percent: 82.0,
        memory_bytes: 1024,
        reason: "detached CLI".to_string(),
        observed_at: "2026-10-12T00:00:00Z".to_string(),
        default_timer_minutes: DEFAULT_TIMER_MINUTES,
    }
}

#[test]
fn pending_enrollment_requires_a_verified_process_generation() {
    let request = test_request();
    let mut policy = PolicyFile::default();
    policy
        .pending
        .insert(request.request_id.clone(), request.clone());
    assert!(policy.validate().is_ok());

    policy
        .pending
        .get_mut(&request.request_id)
        .expect("pending request")
        .identity
        .pid_version = 0;
    assert!(policy.validate().is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn persisted_ui_owner_requires_a_process_generation() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    let owner = UiOwner {
        request_id: "d".repeat(64),
        identity: UiHelperIdentity {
            pid: 123,
            pid_version: 0,
            start_seconds: 1_700_000_000,
            start_microseconds: 123_456,
            user_id: unsafe { libc::getuid() } as u32,
            executable: "/tmp/McpuEnrollment".to_string(),
        },
        last_heartbeat_unix_millis: 10_000,
    };
    store
        .save_ui_owner(&owner)
        .expect("write invalid test owner");
    assert!(store.read_ui_owner().is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn embedded_native_ui_is_installed_in_a_private_cached_app_bundle() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(root.path().join("mcpu"));
    let executable = store
        .prepare_ui_executable()
        .expect("install native enrollment app");
    let metadata = fs::symlink_metadata(&executable).expect("installed executable");
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), unsafe { libc::getuid() });
    assert_eq!(metadata.mode() & 0o777, 0o500);
    assert_eq!(metadata.len(), EMBEDDED_UI_EXECUTABLE.len() as u64);
    let digest_path = store.root.join("ui-source.sha256");
    fs::write(&digest_path, "stale").expect("invalidate UI cache receipt");
    fs::set_permissions(&digest_path, fs::Permissions::from_mode(0o600))
        .expect("keep cache receipt private");
    assert_eq!(
        store
            .prepare_ui_executable()
            .expect("repair stale UI cache receipt"),
        executable
    );
    assert_eq!(
        fs::read_to_string(&digest_path).expect("read UI cache receipt"),
        digest_hex(EMBEDDED_UI_EXECUTABLE)
    );
}

#[test]
fn policy_approval_requires_exact_path_and_fingerprint_and_exclusion_wins() {
    let request = test_request();
    let mut policy = PolicyFile::default();
    policy.approvals.insert(
        request.identity.executable.clone(),
        Approval {
            canonical_path: request.identity.executable.clone(),
            fingerprint: request.identity.fingerprint.clone(),
            timer_minutes: DEFAULT_TIMER_MINUTES,
        },
    );
    assert!(policy.approval_for(&request.identity).is_some());
    policy
        .exclusions
        .insert(request.identity.executable.clone());
    assert!(policy.approval_for(&request.identity).is_none());

    policy.exclusions.clear();
    let mut replaced_binary = request.identity.clone();
    replaced_binary.fingerprint = "e".repeat(64);
    assert!(policy.approval_for(&replaced_binary).is_none());
}

#[test]
fn one_pending_request_deduplicates_the_same_tool_fingerprint() {
    let request = test_request();
    let mut policy = PolicyFile::default();
    policy
        .pending
        .insert(request.request_id.clone(), request.clone());
    assert!(policy.has_pending(&request.identity));
    let mut second_instance = request.identity.clone();
    second_instance.pid += 1;
    second_instance.pid_version += 1;
    second_instance.start_seconds += 1;
    assert!(policy.has_pending(&second_instance));
    let mut changed_binary = request.identity.clone();
    changed_binary.fingerprint = "e".repeat(64);
    assert!(!policy.has_pending(&changed_binary));
}

#[test]
fn durable_pending_enrollment_survives_a_service_restart_without_the_ui() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    let request = test_request();
    {
        let lock = store.lock().expect("lock policy before restart");
        let mut policy = lock.load().expect("load initial policy");
        policy
            .pending
            .insert(request.request_id.clone(), request.clone());
        lock.save(&policy).expect("persist pending request");
    }

    let restarted_store = PolicyStore::new(temp.path().join("mcpu"));
    let lock = restarted_store
        .lock()
        .expect("reopen policy after service restart");
    let recovered = lock.load().expect("recover durable pending request");
    assert_eq!(recovered.pending.get(&request.request_id), Some(&request));
    assert!(recovered.has_pending(&request.identity));
}

#[test]
fn add_and_exclude_are_explicit_and_timer_validation_is_fail_closed() {
    let request = test_request();
    let mut policy = PolicyFile::default();
    policy
        .pending
        .insert(request.request_id.clone(), request.clone());

    let invalid = DecisionResponse {
        request_id: request.request_id.clone(),
        canonical_path: request.identity.executable.clone(),
        fingerprint: request.identity.fingerprint.clone(),
        decision: Decision::Add,
        timer_minutes: Some(0),
    };
    assert!(apply_response(&mut policy, &invalid).is_err());
    assert!(policy.approvals.is_empty());
    assert!(policy.pending.contains_key(&request.request_id));

    let add = DecisionResponse {
        timer_minutes: Some(DEFAULT_TIMER_MINUTES),
        ..invalid
    };
    assert_eq!(
        apply_response(&mut policy, &add).expect("valid Add"),
        DecisionApply::Added {
            minutes: DEFAULT_TIMER_MINUTES
        }
    );
    assert_eq!(
        policy.approvals[&request.identity.executable].timer_minutes,
        DEFAULT_TIMER_MINUTES
    );

    let max_request = test_request();
    let max_request_id = "f".repeat(64);
    let mut max_request = max_request;
    max_request.request_id = max_request_id.clone();
    policy
        .pending
        .insert(max_request_id.clone(), max_request.clone());
    let too_large = DecisionResponse {
        request_id: max_request_id.clone(),
        canonical_path: max_request.identity.executable.clone(),
        fingerprint: max_request.identity.fingerprint.clone(),
        decision: Decision::Add,
        timer_minutes: Some(MAX_TIMER_MINUTES + 1),
    };
    assert!(apply_response(&mut policy, &too_large).is_err());
    assert!(policy.pending.contains_key(&max_request_id));
    let max_timer = DecisionResponse {
        timer_minutes: Some(MAX_TIMER_MINUTES),
        ..too_large
    };
    assert_eq!(
        apply_response(&mut policy, &max_timer).expect("maximum timer boundary"),
        DecisionApply::Added {
            minutes: MAX_TIMER_MINUTES
        }
    );

    let second = test_request();
    policy
        .pending
        .insert(second.request_id.clone(), second.clone());
    let exclude = DecisionResponse {
        request_id: second.request_id.clone(),
        canonical_path: second.identity.executable.clone(),
        fingerprint: second.identity.fingerprint.clone(),
        decision: Decision::Exclude,
        timer_minutes: None,
    };
    assert_eq!(
        apply_response(&mut policy, &exclude).expect("explicit Exclude"),
        DecisionApply::Excluded
    );
    assert!(policy.approvals.is_empty());
    assert!(policy.is_excluded(&second.identity.executable));
    assert!(policy.approval_for(&second.identity).is_none());
}

#[test]
fn changed_or_stale_request_replies_cannot_apply() {
    let request = test_request();
    let mut policy = PolicyFile::default();
    policy
        .pending
        .insert(request.request_id.clone(), request.clone());
    let response = DecisionResponse {
        request_id: request.request_id.clone(),
        canonical_path: request.identity.executable.clone(),
        fingerprint: "c".repeat(64),
        decision: Decision::Add,
        timer_minutes: Some(5),
    };
    assert_eq!(
        apply_response(&mut policy, &response).expect("stale reply"),
        DecisionApply::Stale
    );
    assert!(policy.approvals.is_empty());
    assert!(policy.pending.contains_key(&request.request_id));
}

#[test]
fn add_choice_is_acknowledged_only_after_the_policy_is_durable() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    let lock = store.lock().expect("policy lock");
    let request = test_request();
    let mut policy = PolicyFile::default();
    policy
        .pending
        .insert(request.request_id.clone(), request.clone());
    let response = DecisionResponse {
        request_id: request.request_id.clone(),
        canonical_path: request.identity.executable.clone(),
        fingerprint: request.identity.fingerprint.clone(),
        decision: Decision::Add,
        timer_minutes: Some(17),
    };

    assert_eq!(
        apply_response(&mut policy, &response).expect("apply Add"),
        DecisionApply::Added { minutes: 17 }
    );
    lock.save(&policy).expect("persist approval and completion");
    assert!(lock
        .load()
        .expect("read durable policy")
        .completed
        .contains_key(&request.request_id));

    let response_path = store.response_path(&request.request_id);
    fs::create_dir_all(response_path.parent().expect("response directory"))
        .expect("create response directory");
    fs::write(
        &response_path,
        serde_json::to_vec(&response).expect("encode response"),
    )
    .expect("persist submitted response");

    // A new supervisor generation must recover completion from policy before it
    // removes the response that the UI submitted.
    let mut restarted_policy = lock.load().expect("reload durable decision");
    flush_completed(&store, &lock, &mut restarted_policy)
        .expect("publish acknowledgement and clean response");
    let saved = lock.load().expect("read acknowledged policy");
    assert_eq!(
        saved.approvals[&request.identity.executable].timer_minutes,
        17
    );
    assert!(saved.completed.is_empty());
    assert_eq!(
        read_json_bounded::<UiAcknowledgement>(&store.acknowledgement_path(&request.request_id))
            .expect("read acknowledgement"),
        UiAcknowledgement {
            request_id: response.request_id.clone(),
            canonical_path: response.canonical_path.clone(),
            fingerprint: response.fingerprint.clone(),
            decision: Some(response.decision),
            timer_minutes: response.timer_minutes,
            accepted: true,
            message: None,
        }
    );
    assert!(
        !response_path.exists(),
        "response is removed only after the durable acknowledgement exists"
    );
}

#[test]
fn rejected_choice_has_a_durable_explicit_acknowledgement() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    let request = test_request();

    store
        .write_rejection_acknowledgement(&request, "The timer is invalid.")
        .expect("persist explicit rejection");
    let acknowledgement: UiAcknowledgement =
        read_json_bounded(&store.acknowledgement_path(&request.request_id))
            .expect("read explicit rejection");
    assert!(!acknowledgement.accepted);
    assert_eq!(acknowledgement.request_id, request.request_id);
    assert_eq!(acknowledgement.canonical_path, request.identity.executable);
    assert_eq!(acknowledgement.fingerprint, request.identity.fingerprint);
    assert_eq!(
        acknowledgement.message.as_deref(),
        Some("The timer is invalid.")
    );
}

#[test]
fn version_one_policy_without_completion_receipts_remains_readable() {
    let policy: PolicyFile =
        serde_json::from_str(r#"{"schema_version":1,"approvals":{},"exclusions":[],"pending":{}}"#)
            .expect("legacy policy without optional completion state");
    policy.validate().expect("validate legacy policy");
    assert!(policy.completed.is_empty());
}

#[test]
fn enrollment_queue_and_completion_receipt_sizes_are_bounded() {
    let request = test_request();
    let mut policy = PolicyFile::default();
    for index in 0..=MAX_PENDING_REQUESTS {
        let mut item = request.clone();
        item.request_id = format!("{index:064x}");
        policy.pending.insert(item.request_id.clone(), item);
    }
    assert!(policy.validate().is_err());
}

#[test]
fn private_policy_round_trips_and_corruption_does_not_authorize() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    {
        let lock = store.lock().expect("policy lock");
        let policy = lock.load().expect("empty policy");
        lock.save(&policy).expect("save empty policy");
        assert_eq!(lock.load().expect("read back"), policy);
    }
    fs::write(store.root.join("policy.json"), "{broken").expect("corrupt policy");
    let lock = store.lock().expect("policy lock");
    assert!(lock.load().is_err());
}

#[test]
fn a_held_policy_lock_fails_without_blocking_the_supervisor() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    let _held = store.lock().expect("acquire first policy lock");
    let started = std::time::Instant::now();
    assert!(store.lock().is_err(), "contended lock must fail closed");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(250),
        "policy contention must not block supervisor progress"
    );
}

#[test]
fn first_presentation_prepares_private_response_storage() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    store
        .prepare_response_directory()
        .expect("prepare response storage");
    assert!(store
        .response_path(&"a".repeat(64))
        .parent()
        .unwrap()
        .is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(store.response_path(&"a".repeat(64)).parent().unwrap())
                .expect("response directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn unavailable_policy_storage_cannot_create_a_cleanup_policy() {
    let temp = tempfile::tempdir().expect("temporary policy root");
    let blocking_file = temp.path().join("not-a-directory");
    fs::write(&blocking_file, b"occupied").expect("blocking file");
    let store = PolicyStore::new(blocking_file.join("mcpu"));
    assert!(store.lock().is_err());
}

#[cfg(unix)]
#[test]
fn policy_directory_and_file_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().expect("temporary policy root");
    let store = PolicyStore::new(temp.path().join("mcpu"));
    let lock = store.lock().expect("policy lock");
    lock.save(&PolicyFile::default()).expect("save policy");
    assert_eq!(
        fs::metadata(&store.root)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(store.root.join("policy.json"))
            .expect("policy metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
