//! Versioned wire types shared by the Scriptd automation bridge and the
//! clients that drive it.
//!
//! The bridge performs privileged system operations on behalf of an
//! authenticated client. A client decides *when* an operation should run; the
//! bridge decides whether it is allowed to run and performs it. These types
//! are the only vocabulary both sides share, so the contract lives here rather
//! than in either application.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Protocol version negotiated by both sides of a bridge connection.
///
/// A mismatch is reported rather than tolerated: a client that cannot speak
/// the bridge's protocol must not guess at its semantics.
pub const PROTOCOL_VERSION: u32 = 1;

/// A privileged operation the bridge can perform.
///
/// Capabilities are the vocabulary a client uses to decide what it may ask
/// for. A capability the bridge does not advertise is unavailable; an
/// unavailable capability never satisfies a trigger condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Invoke Homebrew to update formulae, upgrade casks, and clean up.
    HomebrewMaintenance,
    /// Ask Homebrew for the metadata of one installed cask.
    CaskMetadata,
    /// Terminate a running process that a maintenance job is authorized to end.
    ProcessTermination,
    /// Change the current Wi-Fi network.
    WifiNetworkChange,
    /// Observe the current Wi-Fi power and association state.
    WifiObservation,
    /// Observe running applications.
    RunningApplications,
    /// Resolve and report installed package receipt files.
    PackageReceipts,
}

impl Capability {
    /// Every capability this protocol version defines.
    pub fn all() -> &'static [Capability] {
        &[
            Capability::HomebrewMaintenance,
            Capability::CaskMetadata,
            Capability::ProcessTermination,
            Capability::WifiNetworkChange,
            Capability::WifiObservation,
            Capability::RunningApplications,
            Capability::PackageReceipts,
        ]
    }

    /// The stable wire name of this capability.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HomebrewMaintenance => "homebrew_maintenance",
            Self::CaskMetadata => "cask_metadata",
            Self::ProcessTermination => "process_termination",
            Self::WifiNetworkChange => "wifi_network_change",
            Self::WifiObservation => "wifi_observation",
            Self::RunningApplications => "running_applications",
            Self::PackageReceipts => "package_receipts",
        }
    }

    /// Parses a stable wire name back into a capability.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|capability| capability.as_str() == raw)
    }
}

/// A named source the bridge can observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    /// The applications currently running in the console user's session.
    RunningApplications,
    /// The current Wi-Fi power state and association.
    WifiState,
    /// The installed files declared by a package receipt.
    PackageReceipt,
    /// The Homebrew casks that are outdated.
    OutdatedCasks,
}

impl ObservationSource {
    /// Every observation source this protocol version defines.
    pub fn all() -> &'static [ObservationSource] {
        &[
            ObservationSource::RunningApplications,
            ObservationSource::WifiState,
            ObservationSource::PackageReceipt,
            ObservationSource::OutdatedCasks,
        ]
    }

    /// The stable wire name of this observation source.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunningApplications => "running_applications",
            Self::WifiState => "wifi_state",
            Self::PackageReceipt => "package_receipt",
            Self::OutdatedCasks => "outdated_casks",
        }
    }

    /// Parses a stable wire name back into an observation source.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|source| source.as_str() == raw)
    }
}

/// The bridge's report of what it can currently do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// The protocol version the bridge speaks.
    pub protocol_version: u32,
    /// Privileged operations the bridge currently offers.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Observation sources the bridge currently offers.
    #[serde(default)]
    pub observations: Vec<ObservationSource>,
}

impl CapabilityReport {
    /// Reports whether a capability is currently offered.
    pub fn offers(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Reports whether an observation source is currently offered.
    pub fn offers_observation(&self, source: ObservationSource) -> bool {
        self.observations.contains(&source)
    }
}

/// The identity a client presents when it asks to be paired.
///
/// Pairing binds the bridge to a specific code-signing identity so a later
/// client running as a different signer is not silently trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRequest {
    /// The code-signing identity the client presents.
    pub signing_identity: String,
    /// The client application's bundle identifier.
    pub bundle_identifier: String,
    /// The protocol version the client speaks.
    pub protocol_version: u32,
}

/// The bridge's answer to a pairing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingReceipt {
    /// The identity the bridge accepted.
    pub signing_identity: String,
    /// The bundle identifier the bridge accepted.
    pub bundle_identifier: String,
    /// The protocol version the bridge speaks.
    pub protocol_version: u32,
    /// Whether the pairing is currently active.
    pub active: bool,
}

/// A request to observe one named source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRequest {
    /// The source to observe.
    pub source: ObservationSource,
    /// The subject of the observation, such as a package receipt id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// The result of one observation.
///
/// An observation that could not be taken is reported as unavailable with a
/// reason, never as an empty successful result. A client must not read an
/// unavailable observation as an absence of activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationResult {
    /// The source that was observed.
    pub source: ObservationSource,
    /// Whether the observation was taken.
    pub available: bool,
    /// Why the observation was unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The observed values, keyed by the source's own field names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub values: BTreeMap<String, String>,
}

impl ObservationResult {
    /// Reports an observation that could not be taken.
    pub fn unavailable(source: ObservationSource, reason: impl Into<String>) -> Self {
        Self {
            source,
            available: false,
            reason: Some(reason.into()),
            values: BTreeMap::new(),
        }
    }

    /// Reports a successful observation.
    pub fn available(source: ObservationSource, values: BTreeMap<String, String>) -> Self {
        Self {
            source,
            available: true,
            reason: None,
            values,
        }
    }
}

/// A privileged job the bridge has been asked to perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRequest {
    /// The capability the job needs.
    pub capability: Capability,
    /// The module or subject the job applies to, such as a cask name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The arguments the job needs, already validated by the client.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub arguments: BTreeMap<String, String>,
}

/// The result of a privileged job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResult {
    /// The capability the job used.
    pub capability: Capability,
    /// The subject the job applied to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Whether the job completed.
    pub completed: bool,
    /// The job's exit status, when it ran a process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    /// The job's standard output.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    /// The job's standard error.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
    /// Why the job did not complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl JobResult {
    /// Reports a job that never ran because a capability was unavailable.
    pub fn unavailable(capability: Capability, reason: impl Into<String>) -> Self {
        Self {
            capability,
            subject: None,
            completed: false,
            status: None,
            stdout: String::new(),
            stderr: String::new(),
            reason: Some(reason.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Capability, CapabilityReport, JobResult, ObservationResult, ObservationSource,
        PROTOCOL_VERSION, PairingRequest,
    };

    #[test]
    fn capability_names_round_trip() {
        for capability in Capability::all() {
            assert_eq!(Capability::parse(capability.as_str()), Some(*capability));
        }
        assert_eq!(Capability::parse("not_a_capability"), None);
    }

    #[test]
    fn observation_source_names_round_trip() {
        for source in ObservationSource::all() {
            assert_eq!(ObservationSource::parse(source.as_str()), Some(*source));
        }
        assert_eq!(ObservationSource::parse("not_a_source"), None);
    }

    #[test]
    fn capability_names_are_unique() {
        let mut names: Vec<&str> = Capability::all().iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "capability names must be unique");
    }

    #[test]
    fn an_unavailable_capability_is_not_offered() {
        let report = CapabilityReport {
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![Capability::CaskMetadata],
            observations: vec![ObservationSource::RunningApplications],
        };
        assert!(report.offers(Capability::CaskMetadata));
        assert!(
            !report.offers(Capability::HomebrewMaintenance),
            "a capability the bridge does not advertise is unavailable"
        );
        assert!(report.offers_observation(ObservationSource::RunningApplications));
        assert!(!report.offers_observation(ObservationSource::WifiState));
    }

    #[test]
    fn an_unavailable_observation_carries_a_reason_and_no_values() {
        let result = ObservationResult::unavailable(
            ObservationSource::PackageReceipt,
            "receipt is not installed",
        );
        assert!(!result.available);
        assert_eq!(result.reason.as_deref(), Some("receipt is not installed"));
        assert!(result.values.is_empty());
    }

    #[test]
    fn an_unavailable_job_is_never_reported_as_completed() {
        let result = JobResult::unavailable(Capability::HomebrewMaintenance, "bridge absent");
        assert!(!result.completed);
        assert_eq!(result.status, None);
        assert_eq!(result.reason.as_deref(), Some("bridge absent"));
    }

    #[test]
    fn wire_types_round_trip_through_json() {
        let request = PairingRequest {
            signing_identity: "Developer ID Application: Example (TEAM)".to_string(),
            bundle_identifier: "com.astronlab.scriptd".to_string(),
            protocol_version: PROTOCOL_VERSION,
        };
        let encoded = serde_json::to_string(&request).expect("encode pairing request");
        let decoded: PairingRequest =
            serde_json::from_str(&encoded).expect("decode pairing request");
        assert_eq!(decoded, request);
    }
}
