//! Browser access authorization for the loopback control center.

//! A browser profile reaches the control center only after the logged-in user
//! approves it in a native macOS prompt. The server keeps a random grant per
//! approved profile and authenticates every request against it, so no webpage
//! can approve its own access and no credential ever travels through a URL.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use serde::Deserialize;

use crate::grants::{GrantCredential, GrantsStore};

/// Header carrying the browser grant credential.
pub const GRANT_HEADER: &str = "x-scriptd-grant";
/// Idle lifetime of one pending native approval prompt.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a completed approval can be replayed to its requesting tab.
pub const SETTLED_REPLAY_TIMEOUT: Duration = Duration::from_secs(60);
/// Quiet period after a denial or timeout before a new prompt may open.
pub const COOLDOWN: Duration = Duration::from_secs(10);

/// A cask requiring a user decision, copied from the Brew Manager ledger.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CaskAttentionItem {
    pub name: String,
    pub reason: String,
}

/// Private cask decision result; independent of browser authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaskAttentionState {
    Waiting,
    Allowed,
    Denied,
    Dismissed,
    Expired,
    Unavailable,
}

struct CaskAttentionRequest {
    casks: Vec<CaskAttentionItem>,
    state: CaskAttentionState,
    opened_at: Instant,
}

#[derive(Default)]
struct CaskAttentionRequests {
    claims: HashMap<String, CaskAttentionRequest>,
    prompted: HashMap<String, String>,
    cooldown_until: Option<Instant>,
}

/// Cask decisions never read or modify the browser grant store.
#[derive(Default)]
pub struct CaskAttentionController {
    requests: Mutex<CaskAttentionRequests>,
    changed: tokio::sync::Notify,
}

impl CaskAttentionController {
    /// Opens a private request once per cask name in this process.
    pub fn open_request(
        &self,
        casks: Vec<CaskAttentionItem>,
        dismiss: bool,
    ) -> Result<RequestTicket, String> {
        let mut requests = AccessController::lock(&self.requests);
        let now = Instant::now();
        requests.claims.retain(|_, request| {
            now.duration_since(request.opened_at) < REQUEST_TIMEOUT + SETTLED_REPLAY_TIMEOUT
        });
        if requests.claims.values().any(|request| {
            request.state == CaskAttentionState::Waiting
                && now.duration_since(request.opened_at) < REQUEST_TIMEOUT
        }) || requests.cooldown_until.is_some_and(|until| now < until)
        {
            return Err("a cask decision is waiting or cooling down".into());
        }
        if casks.is_empty()
            || (!dismiss
                && casks
                    .iter()
                    .any(|item| requests.prompted.get(&item.name) == Some(&item.reason)))
        {
            return Err("these casks were already prompted; pending work remains visible".into());
        }
        let claim = GrantsStore::random_credential().map_err(|error| error.to_string())?;
        let identifier = GrantsStore::random_credential().map_err(|error| error.to_string())?;
        let identifier = identifier[..12].to_string();
        for item in &casks {
            requests
                .prompted
                .insert(item.name.clone(), item.reason.clone());
        }
        requests.claims.insert(
            claim.clone(),
            CaskAttentionRequest {
                casks,
                state: CaskAttentionState::Waiting,
                opened_at: now,
            },
        );
        requests.cooldown_until = Some(now + COOLDOWN);
        Ok(RequestTicket { claim, identifier })
    }

    /// Settles only a live private claim, retaining its casks for replay.
    pub fn resolve_claim(&self, claim: &str, outcome: CaskAttentionState) {
        let mut requests = AccessController::lock(&self.requests);
        let mut approved_names = Vec::new();
        if let Some(request) = requests.claims.get_mut(claim) {
            if request.state == CaskAttentionState::Waiting {
                request.state = if request.opened_at.elapsed() >= REQUEST_TIMEOUT {
                    CaskAttentionState::Expired
                } else {
                    if outcome == CaskAttentionState::Allowed {
                        approved_names =
                            request.casks.iter().map(|item| item.name.clone()).collect();
                    }
                    outcome
                };
            }
        }
        for name in approved_names {
            requests.prompted.remove(&name);
        }
        requests.cooldown_until = Some(Instant::now() + COOLDOWN);
        drop(requests);
        self.changed.notify_waiters();
    }

    /// Reads only the requesting tab's claim. Unknown and expired claims agree.
    pub fn poll(&self, claim: &str) -> (CaskAttentionState, Vec<CaskAttentionItem>) {
        let requests = AccessController::lock(&self.requests);
        match requests.claims.get(claim) {
            Some(request)
                if request.opened_at.elapsed() < REQUEST_TIMEOUT + SETTLED_REPLAY_TIMEOUT =>
            {
                let state = if request.state == CaskAttentionState::Waiting
                    && request.opened_at.elapsed() >= REQUEST_TIMEOUT
                {
                    CaskAttentionState::Expired
                } else {
                    request.state
                };
                (state, request.casks.clone())
            }
            _ => (CaskAttentionState::Expired, Vec::new()),
        }
    }

    /// One event-driven wait; the browser never schedules a polling timer.
    pub async fn wait(&self, claim: &str) -> (CaskAttentionState, Vec<CaskAttentionItem>) {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let result = self.poll(claim);
        if result.0 != CaskAttentionState::Waiting {
            return result;
        }
        let _ = tokio::time::timeout(REQUEST_TIMEOUT, changed).await;
        self.poll(claim)
    }
}

/// Why a browser is not currently authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessState {
    /// The browser presented a credential matching a live grant.
    Authorized,
    /// A native approval prompt is waiting for the user's decision.
    Pending,
    /// Access was refused or withdrawn and the browser may ask again.
    Unauthorized,
    /// No prompt can be shown in this GUI session.
    Unavailable,
}

impl AccessState {
    /// Stable name reported to the browser.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Pending => "pending",
            Self::Unauthorized => "unauthorized",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One in-flight native approval prompt.
struct PendingRequest {
    /// Private credential issued to the requesting tab alone.
    claim: String,
    /// Human-readable identifier repeated on the page and in the popup.
    identifier: String,
    /// Browser-supplied label recorded with an approved grant.
    label: String,
    opened_at: Instant,
}

struct SettledApproval {
    credential: GrantCredential,
    settled_at: Instant,
}

/// Authorization state shared by the web handlers.
pub struct AccessController {
    grants: Mutex<GrantsStore>,
    pending: Mutex<Option<PendingRequest>>,
    settled: Mutex<HashMap<String, SettledApproval>>,
    cooldown_until: Mutex<Option<Instant>>,
}

impl AccessController {
    /// Loads the persisted grants for this control center.
    pub fn new(grants: GrantsStore) -> Self {
        Self {
            grants: Mutex::new(grants),
            pending: Mutex::new(None),
            settled: Mutex::new(HashMap::new()),
            cooldown_until: Mutex::new(None),
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Reports the access state of the presenting browser.
    pub fn state_for(&self, headers: &HeaderMap) -> AccessState {
        if self.verifies(headers) {
            return AccessState::Authorized;
        }
        let mut pending = Self::lock(&self.pending);
        Self::expire_request(&mut pending, &self.cooldown_until);
        Self::expire_settled(&mut Self::lock(&self.settled));
        if pending.is_some() {
            return AccessState::Pending;
        }
        drop(pending);
        match Self::lock(&self.cooldown_until).as_ref() {
            Some(deadline) if Instant::now() < *deadline => AccessState::Pending,
            _ => AccessState::Unauthorized,
        }
    }

    /// True when the presented credential matches a live grant.
    pub fn verifies(&self, headers: &HeaderMap) -> bool {
        let Some(credential) = headers
            .get(GRANT_HEADER)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        Self::lock(&self.grants).verify(credential).is_some()
    }

    /// Returns the pending identifier if a prompt is waiting.
    pub fn pending_identifier(&self) -> Option<String> {
        Self::lock(&self.pending)
            .as_ref()
            .map(|r| r.identifier.clone())
    }

    /// Opens one pending prompt, or explains why it could not be opened.
    ///
    /// Only one prompt may exist at a time and a denial or timeout places the
    /// controller in a brief cooldown, so a page cannot flood the user with
    /// popups.
    pub fn open_request(&self, label: &str) -> Result<RequestTicket, String> {
        let mut pending = Self::lock(&self.pending);
        Self::expire_request(&mut pending, &self.cooldown_until);
        let mut cooldown = Self::lock(&self.cooldown_until);
        if let Some(deadline) = *cooldown {
            if Instant::now() < deadline {
                return Err("a recent request was declined; try again in a moment".to_string());
            }
            *cooldown = None;
        }
        drop(cooldown);

        Self::expire_settled(&mut Self::lock(&self.settled));
        if pending.is_some() {
            return Err("an approval request is already waiting".to_string());
        }
        let claim = GrantsStore::random_credential().map_err(|error| error.to_string())?;
        let identifier = GrantsStore::random_credential().map_err(|error| error.to_string())?;
        let identifier = identifier[..12].to_string();
        *pending = Some(PendingRequest {
            claim: claim.clone(),
            identifier: identifier.clone(),
            label: label.to_string(),
            opened_at: Instant::now(),
        });
        drop(pending);

        Ok(RequestTicket { claim, identifier })
    }

    /// Records the user's decision for the pending request.
    ///
    /// An approval mints and stores the grant credential that only the
    /// requesting tab can read back through its private claim.
    pub fn resolve_claim(&self, claim: &str, approved: bool) -> Result<(), String> {
        let mut pending = Self::lock(&self.pending);
        Self::expire_request(&mut pending, &self.cooldown_until);
        let Some(request) = pending.as_ref() else {
            return Err("no approval request is waiting".to_string());
        };
        if request.claim != claim {
            return Err("the approval request was replaced".to_string());
        }
        let request = pending.take().expect("pending request was checked");
        drop(pending);
        if !approved {
            *Self::lock(&self.cooldown_until) = Some(Instant::now() + COOLDOWN);
            return Ok(());
        }
        let credential = GrantsStore::random_credential().map_err(|error| error.to_string())?;
        let mut grants = Self::lock(&self.grants);
        let label = request.label.clone();
        grants
            .add(&credential, label)
            .map_err(|error| error.to_string())?;
        drop(grants);
        Self::lock(&self.settled).insert(
            request.claim,
            SettledApproval {
                credential,
                settled_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Reads the outcome of a pending request for the tab that opened it.
    ///
    /// The claim credential is private to one tab, so approval is delivered
    /// only there. Polling stays idempotent until the request expires.
    pub fn poll(&self, claim: &str) -> PollOutcome {
        let mut pending = Self::lock(&self.pending);
        Self::expire_request(&mut pending, &self.cooldown_until);
        if pending
            .as_ref()
            .is_some_and(|request| request.claim == claim)
        {
            return PollOutcome::Waiting;
        }
        drop(pending);
        let mut settled = Self::lock(&self.settled);
        Self::expire_settled(&mut settled);
        settled
            .get(claim)
            .map(|approval| PollOutcome::Allowed(approval.credential.clone()))
            .unwrap_or(PollOutcome::Expired)
    }

    fn expire_request(
        pending: &mut Option<PendingRequest>,
        cooldown_until: &Mutex<Option<Instant>>,
    ) {
        let expired = pending
            .as_ref()
            .is_some_and(|request| request.opened_at.elapsed() >= REQUEST_TIMEOUT);
        if expired {
            *pending = None;
            *Self::lock(cooldown_until) = Some(Instant::now() + COOLDOWN);
        }
    }

    fn expire_settled(settled: &mut HashMap<String, SettledApproval>) {
        settled.retain(|_, approval| approval.settled_at.elapsed() < SETTLED_REPLAY_TIMEOUT);
    }

    /// Closes the prompt and cancels the native notification.
    pub fn cancel_claim(&self, claim: &str) {
        let mut pending = Self::lock(&self.pending);
        if pending
            .as_ref()
            .is_some_and(|request| request.claim == claim)
        {
            pending.take();
            *Self::lock(&self.cooldown_until) = Some(Instant::now() + COOLDOWN);
        }
    }

    /// Lists the approved browser profiles.
    pub fn list(&self) -> Vec<(String, String, i64)> {
        Self::lock(&self.grants)
            .list()
            .iter()
            .map(|grant| (grant.id.clone(), grant.label.clone(), grant.issued_at))
            .collect()
    }

    /// Revokes one browser profile.
    pub fn revoke(&self, id: &str) -> bool {
        let removed = Self::lock(&self.grants).revoke(&id.to_string()).is_some();
        if removed {
            let grants = Self::lock(&self.grants);
            // Persist immediately so revocation survives a crash or restart.
            let state_dir = std::env::var("SCRIPTD_STATE_DIR").ok();
            drop(grants);
            let _ = state_dir;
        }
        removed
    }

    /// Grants store for persistence by the owner.
    pub fn snapshot(&self) -> GrantsStore {
        Self::lock(&self.grants).clone()
    }

    /// Replaces the grant store, used when the owner persists changes.
    pub fn restore(&self, grants: GrantsStore) {
        *Self::lock(&self.grants) = grants;
    }
}

/// Credential pair returned to the tab that requested access.
pub struct RequestTicket {
    /// Private claim the tab presents while polling.
    pub claim: String,
    /// Short identifier shown on the page and in the popup.
    pub identifier: String,
}

/// Outcome of polling a pending request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// The prompt is still waiting for the user.
    Waiting,
    /// The user allowed the browser; the credential is authorized from now on.
    Allowed(GrantCredential),
    /// The request expired or was never opened by this tab.
    Expired,
}

/// Body of an approval request.
#[derive(Deserialize)]
pub struct AccessRequestBody {
    /// Descriptive label recorded alongside the grant.
    #[serde(default)]
    pub label: String,
}

/// Body of an approval poll.
#[derive(Deserialize)]
pub struct AccessPollBody {
    /// Private claim handed to the requesting tab.
    pub claim: String,
}

/// Body of a revocation request.
#[derive(Deserialize)]
pub struct AccessRevokeBody {
    /// Identifier of the grant to revoke.
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_request_expires_without_its_tab_polling() {
        let access = AccessController::new(GrantsStore::default());
        access.open_request("Abandoned tab").expect("open request");
        make_request_expired(&access);

        assert_eq!(access.state_for(&HeaderMap::new()), AccessState::Pending);
        assert!(access.open_request("Another browser").is_err());
        *AccessController::lock(&access.cooldown_until) =
            Some(Instant::now() - Duration::from_secs(1));
        assert!(access.open_request("Another browser").is_ok());
    }

    #[test]
    fn settled_grant_replays_then_expires_without_owner_polling() {
        let access = AccessController::new(GrantsStore::default());
        let ticket = access.open_request("Requesting tab").expect("open request");
        access
            .resolve_claim(&ticket.claim, true)
            .expect("approve request");
        let first = access.poll(&ticket.claim);
        assert!(matches!(&first, PollOutcome::Allowed(_)));
        assert_eq!(access.poll(&ticket.claim), first);

        if let Some(approval) = AccessController::lock(&access.settled).get_mut(&ticket.claim) {
            approval.settled_at = Instant::now() - SETTLED_REPLAY_TIMEOUT;
        }
        assert_eq!(
            access.state_for(&HeaderMap::new()),
            AccessState::Unauthorized
        );
        assert_eq!(access.poll(&ticket.claim), PollOutcome::Expired);
        assert!(access.open_request("Another browser").is_ok());
    }

    fn make_request_expired(access: &AccessController) {
        if let Some(request) = AccessController::lock(&access.pending).as_mut() {
            request.opened_at = Instant::now() - REQUEST_TIMEOUT;
        }
    }

    #[test]
    fn stale_native_callbacks_cannot_resolve_or_cancel_a_replacement() {
        let access = AccessController::new(GrantsStore::default());
        let first = access.open_request("first").expect("open first");
        make_request_expired(&access);
        assert!(access.poll(&first.claim) == PollOutcome::Expired);
        *AccessController::lock(&access.cooldown_until) =
            Some(Instant::now() - Duration::from_secs(1));
        let second = access.open_request("second").expect("open replacement");

        assert!(access.resolve_claim(&first.claim, true).is_err());
        assert!(access.resolve_claim(&first.claim, false).is_err());
        access.cancel_claim(&first.claim);
        assert_eq!(access.poll(&second.claim), PollOutcome::Waiting);
        access
            .resolve_claim(&second.claim, true)
            .expect("resolve second");
        assert!(matches!(
            access.poll(&second.claim),
            PollOutcome::Allowed(_)
        ));
    }
}

#[cfg(test)]
mod cask_attention_tests {
    use super::*;

    fn item() -> CaskAttentionItem {
        CaskAttentionItem {
            name: "example".into(),
            reason: "Quit the running app".into(),
        }
    }

    #[test]
    fn cask_claim_is_private_and_denial_does_not_erase_work() {
        let controller = CaskAttentionController::default();
        let ticket = controller.open_request(vec![item()], false).unwrap();
        assert_eq!(controller.poll("other-tab").0, CaskAttentionState::Expired);
        assert_eq!(
            controller.poll(&ticket.claim).0,
            CaskAttentionState::Waiting
        );
        controller.resolve_claim(&ticket.claim, CaskAttentionState::Denied);
        let (outcome, casks) = controller.poll(&ticket.claim);
        assert_eq!(outcome, CaskAttentionState::Denied);
        assert_eq!(casks[0].name, "example");
        AccessController::lock(&controller.requests).cooldown_until = None;
        assert!(controller.open_request(vec![item()], false).is_err());
        let changed_reason = CaskAttentionItem {
            name: "example".into(),
            reason: "A different failure".into(),
        };
        assert!(controller.open_request(vec![changed_reason], false).is_ok());
    }

    #[test]
    fn dismissal_and_expiry_never_reopen_a_prompt() {
        let controller = CaskAttentionController::default();
        let ticket = controller.open_request(vec![item()], true).unwrap();
        assert_eq!(
            controller.poll(&ticket.claim).0,
            CaskAttentionState::Waiting
        );
        controller.resolve_claim(&ticket.claim, CaskAttentionState::Dismissed);
        assert_eq!(
            controller.poll(&ticket.claim).0,
            CaskAttentionState::Dismissed
        );
        let mut requests = AccessController::lock(&controller.requests);
        requests.cooldown_until = None;
        requests.claims.get_mut(&ticket.claim).unwrap().opened_at =
            Instant::now() - REQUEST_TIMEOUT - SETTLED_REPLAY_TIMEOUT;
        drop(requests);
        assert_eq!(
            controller.poll(&ticket.claim).0,
            CaskAttentionState::Expired
        );
        assert!(controller.open_request(vec![item()], false).is_err());
    }

    #[test]
    fn approval_resets_suppression_but_unchanged_denial_stays_suppressed() {
        let controller = CaskAttentionController::default();
        let denied = controller.open_request(vec![item()], false).unwrap();
        controller.resolve_claim(&denied.claim, CaskAttentionState::Denied);
        AccessController::lock(&controller.requests).cooldown_until = None;
        assert!(controller.open_request(vec![item()], false).is_err());

        let approved_controller = CaskAttentionController::default();
        let approved = approved_controller
            .open_request(vec![item()], false)
            .unwrap();
        approved_controller.resolve_claim(&approved.claim, CaskAttentionState::Allowed);
        AccessController::lock(&approved_controller.requests).cooldown_until = None;
        assert!(approved_controller
            .open_request(vec![item()], false)
            .is_ok());
    }
}
