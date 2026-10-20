//! Demand-driven service snapshot caching for the browser bridge.

use std::future::Future;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::Value;
use tokio::sync::{watch, Mutex as AsyncMutex, Notify};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Snapshot {
    pub digest: String,
    pub value: Value,
}

#[derive(Default)]
struct CacheState {
    epoch: u64,
    built_epoch: Option<u64>,
    current: Option<Arc<Snapshot>>,
}

/// One snapshot per bridge, built only when a subscriber or request needs it.
pub(crate) struct SnapshotCache {
    state: Mutex<CacheState>,
    build_lock: AsyncMutex<()>,
    updates: watch::Sender<Option<Arc<Snapshot>>>,
    invalidated: Notify,
}

impl SnapshotCache {
    pub(crate) fn new() -> Self {
        let (updates, _) = watch::channel(None);
        Self {
            state: Mutex::new(CacheState::default()),
            build_lock: AsyncMutex::new(()),
            updates,
            invalidated: Notify::new(),
        }
    }

    /// Marks all cached data stale without doing snapshot work.
    pub(crate) fn invalidate(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.epoch = state.epoch.wrapping_add(1);
        drop(state);
        self.invalidated.notify_one();
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<Arc<Snapshot>>> {
        self.updates.subscribe()
    }

    pub(crate) fn invalidated(&self) -> &Notify {
        &self.invalidated
    }

    /// Returns the current snapshot, rebuilding once for a burst of invalidations.
    /// Concurrent callers share the same build, and changes during a build cause
    /// one retry before a potentially stale result can be published.
    pub(crate) async fn ensure_current<F, Fut>(&self, build: F) -> Result<Arc<Snapshot>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<(String, Value)>>,
    {
        let _build = self.build_lock.lock().await;
        loop {
            let target_epoch = {
                let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if state.built_epoch == Some(state.epoch) {
                    if let Some(snapshot) = &state.current {
                        return Ok(Arc::clone(snapshot));
                    }
                }
                state.epoch
            };

            let (digest, value) = build().await?;
            let snapshot = Arc::new(Snapshot { digest, value });
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.epoch != target_epoch {
                continue;
            }

            let changed = state
                .current
                .as_deref()
                .map(|current| current != snapshot.as_ref())
                .unwrap_or(true);
            state.built_epoch = Some(target_epoch);
            state.current = Some(Arc::clone(&snapshot));
            drop(state);
            if changed {
                self.updates.send_replace(Some(Arc::clone(&snapshot)));
            }
            return Ok(snapshot);
        }
    }
}

impl Default for SnapshotCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn repeated_reads_reuse_the_cached_snapshot() {
        let cache = SnapshotCache::new();
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::SeqCst);
            async { Ok(("digest".to_string(), serde_json::json!({"ready": true}))) }
        };

        let first = cache.ensure_current(build).await.expect("initial snapshot");
        let second = cache.ensure_current(build).await.expect("cached snapshot");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalidation_does_no_work_until_a_read_needs_fresh_data() {
        let cache = SnapshotCache::new();
        let builds = AtomicUsize::new(0);
        let build = || {
            let value = builds.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok((
                    format!("digest-{value}"),
                    serde_json::json!({"version": value}),
                ))
            }
        };

        cache.ensure_current(build).await.expect("initial snapshot");
        cache.invalidate();
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        let next = cache.ensure_current(build).await.expect("fresh snapshot");
        assert_eq!(next.digest, "digest-1");
        assert_eq!(builds.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_reads_share_one_snapshot_build() {
        let cache = Arc::new(SnapshotCache::new());
        let builds = Arc::new(AtomicUsize::new(0));
        let mut readers = Vec::new();
        for _ in 0..3 {
            let cache = Arc::clone(&cache);
            let builds = Arc::clone(&builds);
            readers.push(tokio::spawn(async move {
                cache
                    .ensure_current(|| {
                        builds.fetch_add(1, Ordering::SeqCst);
                        async {
                            tokio::task::yield_now().await;
                            Ok(("digest".to_string(), serde_json::json!({"ready": true})))
                        }
                    })
                    .await
                    .expect("shared snapshot")
            }));
        }

        for reader in readers {
            reader.await.expect("reader task");
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalidation_during_a_build_retries_before_publishing() {
        let cache = Arc::new(SnapshotCache::new());
        let builds = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let build_cache = Arc::clone(&cache);
        let build_count = Arc::clone(&builds);
        let build_started = Arc::clone(&started);
        let build_release = Arc::clone(&release);
        let task = tokio::spawn(async move {
            build_cache
                .ensure_current(|| {
                    let attempt = build_count.fetch_add(1, Ordering::SeqCst);
                    let started = Arc::clone(&build_started);
                    let release = Arc::clone(&build_release);
                    async move {
                        if attempt == 0 {
                            started.notify_one();
                            release.notified().await;
                        }
                        Ok((
                            format!("digest-{attempt}"),
                            serde_json::json!({"attempt": attempt}),
                        ))
                    }
                })
                .await
                .expect("fresh snapshot")
        });

        started.notified().await;
        cache.invalidate();
        release.notify_one();
        let snapshot = task.await.expect("snapshot task");

        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert_eq!(snapshot.digest, "digest-1");
    }

    #[tokio::test]
    async fn unchanged_rebuilds_do_not_publish_duplicate_updates() {
        let cache = SnapshotCache::new();
        let mut updates = cache.subscribe();
        let build = || async { Ok(("digest".to_string(), serde_json::json!({"ready": true}))) };

        cache.ensure_current(build).await.expect("initial snapshot");
        assert!(updates.changed().await.is_ok());
        cache.invalidate();
        cache
            .ensure_current(build)
            .await
            .expect("unchanged snapshot");

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), updates.changed())
                .await
                .is_err()
        );
    }
}
