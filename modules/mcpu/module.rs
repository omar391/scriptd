#![allow(dead_code)]

#[path = "module/policy.rs"]
mod policy;
#[path = "module/process.rs"]
mod process;

use std::collections::{HashMap, HashSet};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::modules::{ModuleContext, ModuleHealth, ModuleStatus};
use anyhow::{Context, Result};
use policy::{
    apply_response, flush_completed, new_pending, DecisionApply, PendingRequest, PolicyFile,
    PolicyStore, UiHeartbeat, UiOwner, MAX_PENDING_REQUESTS,
};
use process::{Candidate, CpuSampler, ProcessIdentity, MAX_SAMPLE_GAP};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const DISCOVERY_DURATION: Duration = Duration::from_secs(120);
const TERM_GRACE_PERIOD: Duration = Duration::from_secs(60);
const UI_RETRY_BASE_SECONDS: u64 = 5;
const UI_RETRY_MAX_SECONDS: u64 = 300;
const UI_HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "Typed high-CPU process monitor settings.")]
pub(crate) struct McpuConfig {
    #[serde(rename = "cpu_threshold")]
    #[schemars(range(min = 50))]
    cpu_threshold: u64,
    #[serde(rename = "exclude_apps")]
    #[schemars(inner(length(min = 1)), extend("uniqueItems" = true))]
    exclude_apps: Vec<String>,
}

impl Default for McpuConfig {
    fn default() -> Self {
        Self {
            cpu_threshold: 50,
            exclude_apps: vec![
                "Finder".to_string(),
                "Dock".to_string(),
                "Terminal".to_string(),
                "Activity Monitor".to_string(),
                "kernel_task".to_string(),
                "loginwindow".to_string(),
            ],
        }
    }
}

#[derive(Clone, Debug)]
struct TrackedProcess {
    identity: ProcessIdentity,
    first_high_at: Instant,
    last_sample_at: Instant,
}

#[derive(Clone, Debug)]
struct Escalation {
    identity: ProcessIdentity,
    term_sent_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupAction {
    Terminate,
    Kill,
}

enum SignalFailure {
    Shared(anyhow::Error),
    Candidate(anyhow::Error),
}

#[derive(Default)]
struct McpuState {
    sampler: CpuSampler,
    tracked: HashMap<u32, TrackedProcess>,
    escalations: HashMap<u32, Escalation>,
    policy_digest: Option<String>,
    ui_child: Option<Child>,
    ui_request_id: Option<String>,
    ui_owner: Option<UiOwner>,
    ui_failures: u32,
    ui_retry_after: Option<Instant>,
    ui_active: bool,
    eligible_count: u64,
    protected_high_cpu: u64,
    pending_count: u64,
    approval_count: u64,
    exclusion_count: u64,
    last_run_at: Option<String>,
    last_killed_pid: Option<u32>,
    last_term_pid: Option<u32>,
    last_message: Option<String>,
    last_error: Option<String>,
}

static STATE: once_cell::sync::Lazy<std::sync::Mutex<McpuState>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(McpuState::default()));

pub(crate) fn validate_config(config: &McpuConfig) -> anyhow::Result<()> {
    if config.cpu_threshold < 50 {
        anyhow::bail!("mcpu cpu_threshold must be at least 50 percent");
    }
    if config
        .exclude_apps
        .iter()
        .any(|value| value.trim().is_empty() || value.trim() != value)
    {
        anyhow::bail!(
            "mcpu exclude_apps must contain non-empty names without surrounding whitespace"
        );
    }
    let unique_apps = config
        .exclude_apps
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    if unique_apps.len() != config.exclude_apps.len() {
        anyhow::bail!("mcpu exclude_apps must not contain duplicates");
    }
    Ok(())
}

fn read_cpu_config(context: &ModuleContext) -> anyhow::Result<McpuConfig> {
    let Some(crate::config::ModuleSettings::Mcpu(config)) = context.settings.as_ref() else {
        anyhow::bail!("mcpu typed settings were not loaded");
    };
    Ok(config.clone())
}

pub fn run_once(context: &mut ModuleContext) -> anyhow::Result<Option<ModuleStatus>> {
    let mut state = STATE
        .lock()
        .map_err(|_| anyhow::anyhow!("mcpu state lock is poisoned"))?;
    run_once_with_state(context, &mut state, &PolicyStore::system_default())
}

fn run_once_with_state(
    context: &mut ModuleContext,
    state: &mut McpuState,
    store: &PolicyStore,
) -> anyhow::Result<Option<ModuleStatus>> {
    let result = run_once_inner(context, state, store);
    if let Err(error) = &result {
        reset_tracking(state);
        state.sampler.reset();
        state.policy_digest = None;
        let message = format!("mcpu scan failed; monitoring continuity was reset: {error:#}");
        context.logger.error(&message);
        state.last_error = Some(message);
    }
    result
}

fn run_once_inner(
    context: &mut ModuleContext,
    state: &mut McpuState,
    store: &PolicyStore,
) -> anyhow::Result<Option<ModuleStatus>> {
    let config = read_cpu_config(context)?;
    validate_config(&config)?;
    state.last_error = None;
    reap_ui_child(state);

    let policy_lock = store.lock()?;
    let mut policy = policy_lock.load()?;
    let mut policy_changed = false;
    let mut decision_applied = false;
    let mut error_message = state.last_error.clone();

    if !policy.completed.is_empty() {
        match flush_completed(store, &policy_lock, &mut policy) {
            Ok(()) => policy_changed = true,
            Err(error) => {
                error_message = Some(format!(
                    "saved enrollment choice but could not acknowledge it to the UI: {error:#}"
                ));
            }
        }
    }

    let loaded_digest = policy.content_digest()?;
    if state
        .policy_digest
        .as_ref()
        .is_some_and(|previous| previous != &loaded_digest)
    {
        reset_tracking(state);
        policy_changed = true;
    }

    for request_id in policy.pending.keys().cloned().collect::<Vec<_>>() {
        match store.read_response(&request_id) {
            Ok(Some(response)) => {
                let before = policy.clone();
                match apply_response(&mut policy, &response) {
                    Ok(DecisionApply::Stale) => {
                        reject_pending_response(
                            store,
                            &policy,
                            &request_id,
                            "This choice no longer matches the pending request. Choose Add or Exclude again.",
                        )?;
                        error_message =
                            Some("ignored a stale or mismatched enrollment reply".to_string());
                    }
                    Ok(applied) => {
                        if policy != before {
                            if let Err(error) = policy_lock.save(&policy) {
                                policy = before;
                                error_message = Some(format!(
                                    "could not persist enrollment decision: {error:#}"
                                ));
                                break;
                            }
                            policy_changed = true;
                            decision_applied = true;
                            if let Err(error) = flush_completed(store, &policy_lock, &mut policy) {
                                error_message = Some(format!(
                                    "saved enrollment choice but could not acknowledge it to the UI: {error:#}"
                                ));
                            }
                            match applied {
                                DecisionApply::Added { minutes } => {
                                    let message = format!(
                                        "Added CPU cleanup approval with a {minutes}-minute timer"
                                    );
                                    context.logger.info(&message);
                                    state.last_message = Some(message);
                                }
                                DecisionApply::Excluded => {
                                    context.logger.info("Excluded a high-CPU executable");
                                    state.last_message =
                                        Some("Excluded a high-CPU executable".to_string());
                                }
                                DecisionApply::ExcludedAlready => {
                                    context.logger.info(
                                        "Kept an existing executable exclusion; it takes precedence",
                                    );
                                    state.last_message = Some(
                                        "Existing executable exclusion remains in force"
                                            .to_string(),
                                    );
                                }
                                DecisionApply::Stale => {}
                            }
                        } else {
                            store.remove_response(&request_id)?;
                        }
                    }
                    Err(error) => {
                        policy = before;
                        reject_pending_response(
                            store,
                            &policy,
                            &request_id,
                            &format!(
                                "The choice was rejected: {error:#}. Choose Add or Exclude again."
                            ),
                        )?;
                        error_message =
                            Some(format!("rejected invalid enrollment reply: {error:#}"));
                    }
                }
                break;
            }
            Ok(None) => {}
            Err(error) => {
                reject_pending_response(
                    store,
                    &policy,
                    &request_id,
                    "The saved choice could not be read. Choose Add or Exclude again.",
                )?;
                error_message = Some(format!("discarded unreadable enrollment reply: {error:#}"));
                break;
            }
        }
    }

    let snapshot = state
        .sampler
        .sample(&config.exclude_apps, config.cpu_threshold as f32);
    state.eligible_count = snapshot.candidates.len() as u64;
    state.protected_high_cpu = snapshot.protected_high_cpu;
    if let Some(error) = &snapshot.protection_error {
        error_message = Some(format!("process protection scan failed: {error}"));
        reset_tracking(state);
    }
    if !snapshot.warmed || snapshot.discontinuity || policy_changed || decision_applied {
        reset_tracking(state);
    }

    let policy_digest_before_discovery = policy.content_digest()?;
    if !snapshot.warmed || snapshot.discontinuity || policy_changed || decision_applied {
        state.policy_digest = Some(policy_digest_before_discovery.clone());
    }

    let mut seen_tracks = HashMap::<u32, ProcessIdentity>::new();
    let mut seen_escalations = HashMap::<u32, ProcessIdentity>::new();
    let mut added_pending = Vec::<PendingRequest>::new();
    let candidates = if snapshot.warmed
        && !snapshot.discontinuity
        && !policy_changed
        && !decision_applied
        && snapshot.protection_error.is_none()
    {
        snapshot.candidates
    } else {
        Vec::new()
    };

    for candidate in candidates {
        let canonical_path = candidate.identity.executable.as_str();
        if policy.is_excluded(canonical_path) {
            continue;
        }
        if policy.has_pending(&candidate.identity) {
            continue;
        }

        let elapsed = observe_candidate(&mut state.tracked, &candidate, snapshot.at);
        seen_tracks.insert(candidate.identity.pid, candidate.identity.clone());

        if let Some(approval) = policy.approval_for(&candidate.identity).cloned() {
            let timer_seconds = approval
                .timer_minutes
                .checked_mul(60)
                .context("approved timer overflowed seconds")?;
            match cleanup_action(
                state.tracked.get(&candidate.identity.pid),
                state.escalations.get(&candidate.identity.pid),
                Duration::from_secs(timer_seconds),
                snapshot.at,
            ) {
                None => {}
                Some(CleanupAction::Terminate) => {
                    match send_signal(
                        &candidate,
                        &config.exclude_apps,
                        libc::SIGTERM,
                        &policy_lock,
                        &policy,
                    ) {
                        Ok(()) => {
                            state.escalations.insert(
                                candidate.identity.pid,
                                Escalation {
                                    identity: candidate.identity.clone(),
                                    term_sent_at: Instant::now(),
                                },
                            );
                            seen_escalations
                                .insert(candidate.identity.pid, candidate.identity.clone());
                            state.last_term_pid = Some(candidate.identity.pid);
                            let message = format!(
                                "Sent SIGTERM to approved tool PID {} ({})",
                                candidate.identity.pid, candidate.name
                            );
                            context.logger.info(&message);
                            state.last_message = Some(message);
                        }
                        Err(error) => {
                            error_message = Some(record_signal_failure(
                                state,
                                candidate.identity.pid,
                                "SIGTERM",
                                error,
                            ));
                        }
                    }
                }
                Some(CleanupAction::Kill) => {
                    match send_signal(
                        &candidate,
                        &config.exclude_apps,
                        libc::SIGKILL,
                        &policy_lock,
                        &policy,
                    ) {
                        Ok(()) => {
                            state.escalations.remove(&candidate.identity.pid);
                            state.tracked.remove(&candidate.identity.pid);
                            state.last_killed_pid = Some(candidate.identity.pid);
                            let message = format!(
                                "Sent SIGKILL to approved tool PID {} after the grace period",
                                candidate.identity.pid
                            );
                            context.logger.info(&message);
                            state.last_message = Some(message);
                        }
                        Err(error) => {
                            error_message = Some(record_signal_failure(
                                state,
                                candidate.identity.pid,
                                "SIGKILL",
                                error,
                            ));
                        }
                    }
                }
            }
            if state
                .escalations
                .get(&candidate.identity.pid)
                .is_some_and(|entry| entry.identity == candidate.identity)
            {
                seen_escalations.insert(candidate.identity.pid, candidate.identity.clone());
            }
            continue;
        }

        if elapsed >= DISCOVERY_DURATION {
            if policy.pending.len() >= MAX_PENDING_REQUESTS {
                error_message = Some(format!(
                    "enrollment queue reached its {MAX_PENDING_REQUESTS}-request safety limit"
                ));
                continue;
            }
            let observed_at = chrono::Utc::now().to_rfc3339();
            let request = new_pending(&candidate, observed_at)?;
            policy
                .pending
                .insert(request.request_id.clone(), request.clone());
            added_pending.push(request);
        }
    }

    reconcile_tracking(&mut state.tracked, &seen_tracks);
    reconcile_escalations(&mut state.escalations, &seen_escalations);

    if !added_pending.is_empty() {
        match policy_lock.save(&policy) {
            Ok(()) => {
                reset_tracking(state);
                state.policy_digest = Some(policy.content_digest()?);
                for request in &added_pending {
                    context.logger.info(&format!(
                        "Created first-time enrollment request for {} ({:.1}% CPU)",
                        request.name, request.cpu_percent
                    ));
                }
            }
            Err(error) => {
                for request in &added_pending {
                    policy.pending.remove(&request.request_id);
                }
                error_message = Some(format!("could not persist pending enrollment: {error:#}"));
            }
        }
    } else if state.policy_digest.is_none() {
        state.policy_digest = Some(policy.content_digest()?);
    } else if !policy_changed && !decision_applied {
        state.policy_digest = Some(policy_digest_before_discovery);
    }

    let next_request = policy
        .pending
        .values()
        .min_by(|left, right| left.observed_at.cmp(&right.observed_at))
        .cloned();
    state.pending_count = policy.pending.len() as u64;
    state.approval_count = policy.approvals.len() as u64;
    state.exclusion_count = policy.exclusions.len() as u64;
    drop(policy_lock);

    if let Some(error) = error_message {
        context.logger.error(&error);
        state.last_error = Some(error);
    } else {
        state.last_error = snapshot.protection_error;
    }
    match update_ui_health(store, state) {
        Ok(()) => {}
        Err(error) => {
            let message = format!("could not verify native enrollment UI health: {error:#}");
            context.logger.error(&message);
            state.last_error = Some(message);
            state.ui_active = true;
        }
    }
    if !state.ui_active {
        if let Some(request) = next_request {
            if let Err(error) = present_request(store, &request, state, snapshot.at) {
                let message =
                    format!("enrollment remains pending; UI could not be presented: {error:#}");
                context.logger.error(&message);
                schedule_ui_retry(state);
                state.last_error = Some(message);
            }
        }
    }
    state.last_run_at = Some(chrono::Utc::now().to_rfc3339());

    Ok(Some(status_from_state(state)))
}

fn observe_candidate(
    tracked: &mut HashMap<u32, TrackedProcess>,
    candidate: &Candidate,
    now: Instant,
) -> Duration {
    let entry = tracked
        .entry(candidate.identity.pid)
        .or_insert_with(|| TrackedProcess {
            identity: candidate.identity.clone(),
            first_high_at: now,
            last_sample_at: now,
        });
    if entry.identity != candidate.identity
        || now.saturating_duration_since(entry.last_sample_at) > MAX_SAMPLE_GAP
    {
        *entry = TrackedProcess {
            identity: candidate.identity.clone(),
            first_high_at: now,
            last_sample_at: now,
        };
    } else {
        entry.last_sample_at = now;
    }
    now.saturating_duration_since(entry.first_high_at)
}

fn cleanup_action(
    tracked: Option<&TrackedProcess>,
    escalation: Option<&Escalation>,
    timer: Duration,
    now: Instant,
) -> Option<CleanupAction> {
    let tracked = tracked?;
    if now.saturating_duration_since(tracked.first_high_at) < timer
        || now.saturating_duration_since(tracked.last_sample_at) > MAX_SAMPLE_GAP
    {
        return None;
    }
    match escalation {
        None => Some(CleanupAction::Terminate),
        Some(escalation)
            if escalation.identity == tracked.identity
                && now.saturating_duration_since(escalation.term_sent_at) >= TERM_GRACE_PERIOD =>
        {
            Some(CleanupAction::Kill)
        }
        Some(_) => None,
    }
}

fn reconcile_tracking(
    tracked: &mut HashMap<u32, TrackedProcess>,
    seen: &HashMap<u32, ProcessIdentity>,
) {
    tracked.retain(|pid, entry| seen.get(pid) == Some(&entry.identity));
}

fn reconcile_escalations(
    escalations: &mut HashMap<u32, Escalation>,
    seen: &HashMap<u32, ProcessIdentity>,
) {
    escalations.retain(|pid, entry| seen.get(pid) == Some(&entry.identity));
}

fn reset_tracking(state: &mut McpuState) {
    state.tracked.clear();
    state.escalations.clear();
}

fn reject_pending_response(
    store: &PolicyStore,
    policy: &PolicyFile,
    request_id: &str,
    message: &str,
) -> Result<()> {
    store.remove_response(request_id)?;
    if let Some(request) = policy.pending.get(request_id) {
        store.write_rejection_acknowledgement(request, message)?;
    }
    Ok(())
}

fn send_signal(
    candidate: &Candidate,
    exclude_apps: &[String],
    signal: i32,
    policy_lock: &policy::PolicyLock<'_>,
    policy: &PolicyFile,
) -> std::result::Result<(), SignalFailure> {
    policy_lock.save(policy).map_err(|error| {
        SignalFailure::Shared(error.context("policy storage is not writable before cleanup"))
    })?;
    if policy.is_excluded(&candidate.identity.executable)
        || policy.approval_for(&candidate.identity).is_none()
    {
        return Err(SignalFailure::Candidate(anyhow::anyhow!(
            "cleanup approval is missing, stale, or excluded"
        )));
    }
    process::verify_current_identity(&candidate.identity, exclude_apps).map_err(
        |error| match error {
            process::CleanupCheckError::Shared(error) => SignalFailure::Shared(error),
            process::CleanupCheckError::Candidate(error) => SignalFailure::Candidate(error),
        },
    )?;
    process::signal_process_generation(
        candidate.identity.pid,
        candidate.identity.pid_version,
        signal,
    )
    .map_err(|error| SignalFailure::Candidate(anyhow::Error::from(error)))
}

fn record_signal_failure(
    state: &mut McpuState,
    pid: u32,
    signal_name: &str,
    failure: SignalFailure,
) -> String {
    match failure {
        SignalFailure::Shared(error) => {
            reset_tracking(state);
            format!("refused or failed {signal_name} for PID {pid}: {error:#}")
        }
        SignalFailure::Candidate(error) => {
            state.tracked.remove(&pid);
            state.escalations.remove(&pid);
            format!("refused or failed {signal_name} for PID {pid}: {error:#}")
        }
    }
}

fn send_signal_with<V, S>(candidate: &Candidate, signal: i32, verify: V, send: S) -> Result<()>
where
    V: FnOnce(&ProcessIdentity) -> Result<()>,
    S: FnOnce(&ProcessIdentity, i32) -> std::io::Result<()>,
{
    verify(&candidate.identity)
        .context("process failed immediate identity and protection recheck")?;
    send(&candidate.identity, signal).context("send identity-bound individual process signal")
}

fn update_ui_health(store: &PolicyStore, state: &mut McpuState) -> Result<()> {
    let lock_held = policy::try_ui_lock(&store.ui_lock_path())?;
    if !lock_held && state.ui_child.is_none() {
        store.clear_ui_health()?;
        state.ui_owner = None;
        state.ui_active = false;
        return Ok(());
    }

    state.ui_active = true;
    let now_millis = current_unix_millis()?;
    let heartbeat = match store.read_ui_heartbeat() {
        Ok(heartbeat) => heartbeat,
        Err(error) => {
            state.last_error = Some(format!(
                "native enrollment heartbeat is unreadable: {error:#}"
            ));
            return Ok(());
        }
    };

    if let Some(heartbeat) = heartbeat.as_ref() {
        if heartbeat_is_fresh(heartbeat, now_millis) {
            match process::capture_ui_helper_identity(heartbeat.pid, &store.ui_executable_path()) {
                Ok(identity) => {
                    let owner = UiOwner {
                        request_id: heartbeat.request_id.clone(),
                        identity,
                        last_heartbeat_unix_millis: heartbeat.unix_millis,
                    };
                    store.save_ui_owner(&owner)?;
                    state.ui_owner = Some(owner);
                    state.ui_failures = 0;
                    state.ui_retry_after = None;
                    return Ok(());
                }
                Err(error) => {
                    state.last_error = Some(format!(
                        "native enrollment heartbeat process could not be verified: {error:#}"
                    ));
                    return Ok(());
                }
            }
        }
    }

    let persisted_owner = store.read_ui_owner()?;
    let mut owner = persisted_owner.or_else(|| state.ui_owner.clone());
    let startup_owner = if owner.is_none() {
        match (state.ui_child.as_ref(), state.ui_request_id.as_ref()) {
            (Some(child), Some(request_id)) => {
                match process::capture_ui_helper_identity(child.id(), &store.ui_executable_path()) {
                    Ok(identity) => {
                        let owner = UiOwner {
                            request_id: request_id.clone(),
                            identity,
                            last_heartbeat_unix_millis: now_millis,
                        };
                        store.save_ui_owner(&owner)?;
                        Some(owner)
                    }
                    Err(_) => None,
                }
            }
            _ => None,
        }
    } else {
        None
    };
    if owner.is_none() {
        owner = startup_owner;
    }
    let Some(owner) = owner else {
        state.last_error = Some(
            "enrollment remains pending; the open UI process identity is not yet verifiable"
                .to_string(),
        );
        return Ok(());
    };

    if let Some(heartbeat) = heartbeat.as_ref() {
        if !heartbeat_matches_owner(heartbeat, &owner) {
            state.last_error = Some(
                "enrollment remains pending; the UI heartbeat does not match its recorded process"
                    .to_string(),
            );
            return Ok(());
        }
    }

    let current = match process::capture_ui_helper_identity(
        owner.identity.pid,
        &store.ui_executable_path(),
    ) {
        Ok(current) => current,
        Err(error) => {
            state.last_error = Some(format!(
                "enrollment UI identity could not be reverified; leaving the prompt pending: {error:#}"
            ));
            return Ok(());
        }
    };
    if current != owner.identity {
        state.last_error = Some(
            "enrollment UI identity changed; leaving the open prompt and pending request untouched"
                .to_string(),
        );
        return Ok(());
    }

    let last_seen = heartbeat
        .as_ref()
        .map(|heartbeat| heartbeat.unix_millis)
        .unwrap_or(owner.last_heartbeat_unix_millis);
    if now_millis
        .checked_sub(last_seen)
        .is_some_and(|age| age >= UI_HEARTBEAT_STALE_AFTER.as_millis() as i64)
    {
        stop_unresponsive_ui_helper(&owner)?;
        state.last_error = Some(
            "stopped an unresponsive enrollment UI helper; the durable request remains pending"
                .to_string(),
        );
    }
    state.ui_owner = Some(owner);
    Ok(())
}

fn stop_unresponsive_ui_helper(owner: &UiOwner) -> Result<()> {
    stop_ui_helper_with(owner, |pid, pid_version, signal| {
        process::signal_process_generation(pid, pid_version, signal)
    })
}

fn stop_ui_helper_with<S>(owner: &UiOwner, signal: S) -> Result<()>
where
    S: FnOnce(u32, u32, i32) -> std::io::Result<()>,
{
    signal(
        owner.identity.pid,
        owner.identity.pid_version,
        libc::SIGKILL,
    )
    .context("stop an unresponsive enrollment UI helper")
}

fn send_signal_with_policy_persistence<P, V, S>(
    candidate: &Candidate,
    signal: i32,
    persist_policy: P,
    verify: V,
    send: S,
) -> Result<()>
where
    P: FnOnce() -> Result<()>,
    V: FnOnce(&ProcessIdentity) -> Result<()>,
    S: FnOnce(&ProcessIdentity, i32) -> std::io::Result<()>,
{
    persist_policy().context("policy storage is not writable before cleanup")?;
    send_signal_with(candidate, signal, verify, send)
}

fn heartbeat_is_fresh(heartbeat: &UiHeartbeat, now_unix_millis: i64) -> bool {
    match now_unix_millis.checked_sub(heartbeat.unix_millis) {
        Some(age) => age < UI_HEARTBEAT_STALE_AFTER.as_millis() as i64,
        None => true,
    }
}

fn heartbeat_matches_owner(heartbeat: &UiHeartbeat, owner: &UiOwner) -> bool {
    heartbeat.request_id == owner.request_id && heartbeat.pid == owner.identity.pid
}

fn current_unix_millis() -> Result<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    i64::try_from(millis).context("system clock milliseconds overflowed")
}

fn reap_ui_child(state: &mut McpuState) {
    let outcome = state.ui_child.as_mut().map(Child::try_wait);
    match outcome {
        Some(Ok(Some(status))) => {
            state.ui_child = None;
            state.ui_request_id = None;
            if status.success() {
                state.ui_failures = 0;
                state.ui_retry_after = None;
            } else {
                schedule_ui_retry(state);
                state.last_error = Some(format!(
                    "native enrollment UI exited without a choice ({status})"
                ));
            }
        }
        Some(Ok(None)) | None => {}
        Some(Err(error)) => {
            state.ui_child = None;
            schedule_ui_retry(state);
            state.last_error = Some(format!("could not inspect enrollment UI process: {error}"));
        }
    }
}

fn schedule_ui_retry(state: &mut McpuState) {
    state.ui_failures = state.ui_failures.saturating_add(1).min(7);
    let multiplier = 1_u64 << state.ui_failures.saturating_sub(1);
    let seconds = UI_RETRY_BASE_SECONDS
        .saturating_mul(multiplier)
        .min(UI_RETRY_MAX_SECONDS);
    state.ui_retry_after = Some(Instant::now() + Duration::from_secs(seconds));
}

fn present_request(
    store: &PolicyStore,
    request: &PendingRequest,
    state: &mut McpuState,
    now: Instant,
) -> Result<()> {
    if state.ui_active || state.ui_child.is_some() {
        return Ok(());
    }
    let request_path = store.ensure_request(request)?;
    store.prepare_response_directory()?;
    let response_path = store.response_path(&request.request_id);
    if response_path.exists() {
        return Ok(());
    }
    if state
        .ui_retry_after
        .is_some_and(|retry_after| now < retry_after)
    {
        return Ok(());
    }
    let lock_path = store.ui_lock_path();
    if policy::try_ui_lock(&lock_path)? {
        state.ui_active = true;
        return Ok(());
    }
    let executable_path = store.prepare_ui_executable()?;
    let child = Command::new(&executable_path)
        .arg(request_path)
        .arg(response_path)
        .arg(lock_path)
        .arg(store.acknowledgement_path(&request.request_id))
        .arg(store.ui_heartbeat_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start native AppKit enrollment UI")?;
    state.ui_child = Some(child);
    state.ui_request_id = Some(request.request_id.clone());
    state.ui_owner = None;
    state.ui_active = true;
    state.last_message = Some(format!("Waiting for Add or Exclude for {}", request.name));
    Ok(())
}

fn status_from_state(state: &McpuState) -> ModuleStatus {
    let metrics = HashMap::from([
        (
            "tracked".to_string(),
            serde_json::Value::from(state.tracked.len() as u64),
        ),
        (
            "eligible_cli".to_string(),
            serde_json::Value::from(state.eligible_count),
        ),
        (
            "protected_high_cpu".to_string(),
            serde_json::Value::from(state.protected_high_cpu),
        ),
        (
            "pending_enrollment".to_string(),
            serde_json::Value::from(state.pending_count),
        ),
        (
            "approved_tools".to_string(),
            serde_json::Value::from(state.approval_count),
        ),
        (
            "excluded_tools".to_string(),
            serde_json::Value::from(state.exclusion_count),
        ),
        (
            "ui_active".to_string(),
            serde_json::Value::from(state.ui_active),
        ),
        (
            "last_term_pid".to_string(),
            serde_json::Value::from(
                state
                    .last_term_pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "none".to_string()),
            ),
        ),
        (
            "last_killed_pid".to_string(),
            serde_json::Value::from(
                state
                    .last_killed_pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "none".to_string()),
            ),
        ),
        (
            "last_error".to_string(),
            serde_json::Value::from(
                state
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
            ),
        ),
    ]);
    ModuleStatus {
        state: "running".to_string(),
        message: state.last_message.clone(),
        started_at: None,
        last_run_at: state.last_run_at.clone(),
        next_run_at: None,
        metrics: Some(metrics),
    }
}

pub fn setup(_context: &mut ModuleContext) -> anyhow::Result<()> {
    Ok(())
}

pub fn status() -> Option<(ModuleStatus, ModuleHealth)> {
    let state = STATE.lock().ok()?;
    let mut status = status_from_state(&state);
    if state.last_run_at.is_none() {
        status.state = "stopped".to_string();
        status.message = Some("not run yet".to_string());
    }
    Some((
        status,
        ModuleHealth {
            ok: state.last_error.is_none(),
            message: state
                .last_error
                .clone()
                .or_else(|| Some("cpu monitor healthy".to_string())),
        },
    ))
}

#[cfg(test)]
#[path = "module/tests.rs"]
mod tests;
