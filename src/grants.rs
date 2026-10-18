//! Browser authorization grant store.

//! A browser profile retains a random grant credential in origin-scoped storage.
//! The server stores a hash of that credential and uses it to authenticate all
//! requests. Each browser has its own grant; revocation is per-profile without
//! affecting other authorized browsers.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::control::ControlPaths;
use crate::paths::write_private_atomic;

/// A unique identifier for a browser grant.
pub type GrantId = String;

/// The raw credential stored in the browser (not persisted on the server).
pub type GrantCredential = String;

/// SHA-256 hash of a grant credential.
pub type CredentialHash = String;

/// A browser authorization grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserGrant {
    /// Unique identifier for this grant.
    pub id: GrantId,
    /// SHA-256 hash of the browser-stored credential.
    pub credential_hash: CredentialHash,
    /// Browser-provided label (e.g., "Safari on MacBook Pro").
    pub label: String,
    /// Unix timestamp when this grant was issued.
    pub issued_at: i64,
}

/// The persisted grants store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantsStore {
    grants: HashMap<GrantId, BrowserGrant>,
}

impl Default for GrantsStore {
    fn default() -> Self {
        Self {
            grants: HashMap::new(),
        }
    }
}

impl GrantsStore {
    /// Path to the grants file for a given state directory.
    pub fn path(paths: &ControlPaths) -> PathBuf {
        paths.state_dir.join("browser-grants.json")
    }

    /// Load the grants store from disk, creating an empty one if missing.
    pub fn load(paths: &ControlPaths) -> Result<Self> {
        let path = Self::path(paths);
        match fs::read_to_string(&path) {
            Ok(raw) => {
                let mut store: Self = serde_json::from_str(&raw)
                    .context("parse browser grants file")?;
                // Prune malformed entries.
                store.grants.retain(|_, grant| {
                    grant.id.len() == 32
                        && grant.credential_hash.starts_with("sha256:")
                        && grant.credential_hash.len() == 6 + 64
                        && grant.issued_at > 0
                });
                Ok(store)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).context("read browser grants file"),
        }
    }

    /// Persist the grants store to disk with 0600 permissions.
    pub fn save(&self, paths: &ControlPaths) -> Result<()> {
        let path = Self::path(paths);
        let content = serde_json::to_string_pretty(self)
            .context("serialize browser grants")?;
        write_private_atomic(&path, content.as_bytes())
            .context("write browser grants file")
    }

    /// Generate a new random grant credential.
    pub fn random_credential() -> Result<GrantCredential> {
        let mut bytes = [0u8; 32];
        fs::File::open("/dev/urandom")
            .context("open random source")?
            .read_exact(&mut bytes)?;
        Ok(hex::encode(bytes))
    }

    /// Compute the SHA-256 hash of a credential.
    pub fn hash_credential(credential: &str) -> CredentialHash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(credential.as_bytes());
        let hash = hasher.finalize();
        format!("sha256:{}", hex::encode(hash))
    }

    /// Add a new grant with the given credential and label.
    pub fn add(&mut self, credential: &GrantCredential, label: String) -> Result<BrowserGrant> {
        let id = Self::random_credential()?;
        let credential_hash = Self::hash_credential(credential);
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let grant = BrowserGrant {
            id: id.clone(),
            credential_hash,
            label,
            issued_at,
        };
        self.grants.insert(id, grant.clone());
        Ok(grant)
    }

    /// Look up a grant by its credential hash.
    pub fn verify(&self, credential: &str) -> Option<&BrowserGrant> {
        let hash = Self::hash_credential(credential);
        self.grants.values().find(|g| g.credential_hash == hash)
    }

    /// Remove a grant by its ID.
    pub fn revoke(&mut self, id: &GrantId) -> Option<BrowserGrant> {
        self.grants.remove(id)
    }

    /// List all grants.
    pub fn list(&self) -> Vec<&BrowserGrant> {
        self.grants.values().collect()
    }

    /// Count active grants.
    pub fn count(&self) -> usize {
        self.grants.len()
    }
}
