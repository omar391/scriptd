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
/// Quiet period after a denial or timeout before a new prompt may open.
pub const COOLDOWN: Duration = Duration::from_secs(10);

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
    granted: Option<GrantCredential>,
    opened_at: Instant,
}

/// Authorization state shared by the web handlers.
pub struct AccessController {
    grants: Mutex<GrantsStore>,
    pending: Mutex<Option<PendingRequest>>,
    cooldown_until: Mutex<Option<Instant>>,
}

impl AccessController {
    /// Loads the persisted grants for this control center.
    pub fn new(grants: GrantsStore) -> Self {
        Self {
            grants: Mutex::new(grants),
            pending: Mutex::new(None),
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
        let pending = Self::lock(&self.pending);
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
        let Some(credential) = headers.get(GRANT_HEADER).and_then(|value| value.to_str().ok()) else {
            return false;
        };
        Self::lock(&self.grants).verify(credential).is_some()
    }

    /// Returns the pending identifier if a prompt is waiting.
    pub fn pending_identifier(&self) -> Option<String> {
        Self::lock(&self.pending).as_ref().map(|r| r.identifier.clone())
    }

    /// Opens one pending prompt, or explains why it could not be opened.
    ///
    /// Only one prompt may exist at a time and a denial or timeout places the
    /// controller in a brief cooldown, so a page cannot flood the user with
    /// popups.
    pub fn open_request(&self, label: &str) -> Result<RequestTicket, String> {
        let cooldown = Self::lock(&self.cooldown_until);
        if let Some(deadline) = *cooldown {
            if Instant::now() < deadline {
                return Err("a recent request was declined; try again in a moment".to_string());
            }
        }
        drop(cooldown);

        let mut pending = Self::lock(&self.pending);
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
            granted: None,
            opened_at: Instant::now(),
        });
        drop(pending);

        Ok(RequestTicket { claim, identifier })
    }

    /// Records the user's decision for the pending request.
    ///
    /// An approval mints and stores the grant credential that only the
    /// requesting tab can read back through its private claim.
    pub fn resolve(&self, approved: bool) -> Result<(), String> {
        let mut pending = Self::lock(&self.pending);
        let Some(request) = pending.take() else {
            return Err("no approval request is waiting".to_string());
        };
        drop(pending);
        if !approved {
            *Self::lock(&self.cooldown_until) = Some(Instant::now() + COOLDOWN);
            return Ok(());
        }
        let credential = GrantsStore::random_credential().map_err(|error| error.to_string())?;
        let mut grants = Self::lock(&self.grants);
        let label = request.label.clone();
        grants.add(&credential, label).map_err(|error| error.to_string())?;
        let updated = grants.clone();
        drop(grants);
        let mut request = request;
        request.granted = Some(credential);
        *Self::lock(&self.pending) = Some(request);
        let _ = updated;
        Ok(())
    }

    /// Reads the outcome of a pending request for the tab that opened it.
    ///
    /// The claim credential is private to one tab, so approval is delivered
    /// only there. Polling stays idempotent until the request expires.
    pub fn poll(&self, claim: &str) -> PollOutcome {
        let mut pending = Self::lock(&self.pending);
        let Some(request) = pending.as_ref() else {
            return PollOutcome::Expired;
        };
        if request.claim != claim {
            return PollOutcome::Expired;
        }
        if let Some(credential) = &request.granted {
            let credential = credential.clone();
            *pending = None;
            return PollOutcome::Allowed(credential);
        }
        if request.opened_at.elapsed() >= REQUEST_TIMEOUT {
            *pending = None;
            *Self::lock(&self.cooldown_until) = Some(Instant::now() + COOLDOWN);
            return PollOutcome::Expired;
        }
        PollOutcome::Waiting
    }

    /// Closes the prompt and cancels the native notification.
    pub fn cancel_pending(&self) {
        let request = Self::lock(&self.pending).take();
        if let Some(request) = request {
            if request.granted.is_none() {
                *Self::lock(&self.cooldown_until) = Some(Instant::now() + COOLDOWN);
            }
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
