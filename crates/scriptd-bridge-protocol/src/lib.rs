//! Versioned wire types shared by the Scriptd automation bridge and the
//! clients that drive it.
//!
//! The bridge performs privileged system operations on behalf of an
//! authenticated client. A client decides *when* an operation should run; the
//! bridge decides whether it is allowed to run and performs it. These types
//! are the only vocabulary both sides share, so the contract lives here rather
//! than in either application.

use serde::{Deserialize, Serialize};

/// Protocol version negotiated by both sides of a bridge connection.
///
/// A mismatch is reported rather than tolerated: a client that cannot speak
/// the bridge's protocol must not guess at its semantics.
pub const PROTOCOL_VERSION: u32 = 3;
/// First protocol version with the fixed, approved package-installer operation.
pub const INSTALLER_PROTOCOL_VERSION: u32 = 4;

/// A privileged operation the bridge can perform.
///
/// Capabilities are the vocabulary a client uses to decide what it may ask
/// for. A capability the bridge does not advertise is unavailable; an
/// unavailable capability never satisfies a trigger condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Change the current Wi-Fi network.
    WifiNetworkChange,
    /// Install a publisher-approved signed macOS package through the native installer.
    InstallerPackageV1,
}

impl Capability {
    /// Every capability this protocol version defines.
    pub fn all() -> &'static [Capability] {
        &[
            Capability::WifiNetworkChange,
            Capability::InstallerPackageV1,
        ]
    }

    /// The stable wire name of this capability.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WifiNetworkChange => "wifi_network_change",
            Self::InstallerPackageV1 => "installer_package_v1",
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

/// The bridge's report of what it can currently do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    /// The protocol version the bridge speaks.
    pub protocol_version: u32,
    /// Privileged operations the bridge currently offers.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

impl CapabilityReport {
    /// Reports whether a capability is currently offered.
    pub fn offers(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// A client asks to be paired using only its application identifier. The
/// bridge derives the signing identity from the authenticated socket peer;
/// callers cannot claim an identity in protocol data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    /// The client application's expected bundle identifier.
    pub bundle_identifier: String,
    /// The protocol version the client speaks.
    pub protocol_version: u32,
}

/// The bridge's answer to a pairing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Read-only pairing state for the authenticated application peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingStatus {
    /// The protocol version the bridge speaks.
    pub protocol_version: u32,
    /// The bundle identifier derived from the authenticated peer.
    pub bundle_identifier: String,
    /// Whether this exact peer identity currently has an active pairing.
    pub active: bool,
}

/// Stable idempotency key assigned by the app before submitting an operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    /// Constructs an identifier that is safe to persist and reconcile.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err("operation id must be 1 to 128 safe ASCII characters");
        }
        Ok(Self(value))
    }

    /// Returns the stable wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

/// A narrowly scoped operation; it contains no command, executable path, or script field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    SetWifiNetwork {
        ssid: String,
    },
    /// Install a package whose publisher and package identifier have a separate
    /// administrator grant. `package_path` is only an untrusted source path;
    /// the broker copies it into protected staging before inspection/use.
    InstallApprovedPackage {
        package_identifier: String,
        package_path: String,
    },
}

impl Operation {
    /// Returns the capability required to run this operation.
    pub fn capability(&self) -> Capability {
        match self {
            Self::SetWifiNetwork { .. } => Capability::WifiNetworkChange,
            Self::InstallApprovedPackage { .. } => Capability::InstallerPackageV1,
        }
    }

    /// Checks operation arguments before they enter the privileged service.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::SetWifiNetwork { ssid } => {
                if ssid.trim().is_empty() || ssid.len() > 32 || ssid.chars().any(char::is_control) {
                    return Err(
                        "Wi-Fi network name must be 1 to 32 bytes without control characters",
                    );
                }
                Ok(())
            }
            Self::InstallApprovedPackage {
                package_identifier,
                package_path,
            } => {
                if package_identifier.is_empty()
                    || package_identifier.len() > 255
                    || !package_identifier.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
                {
                    return Err("package identifier is invalid");
                }
                if !package_path.starts_with('/')
                    || package_path.len() > 4096
                    || package_path.chars().any(char::is_control)
                    || !package_path.to_ascii_lowercase().ends_with(".pkg")
                {
                    return Err("package source path must be an absolute .pkg path without control characters");
                }
                Ok(())
            }
        }
    }
}

/// A versioned operation submission. The ID is chosen and persisted by the app first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub protocol_version: u32,
    pub operation_id: OperationId,
    pub operation: Operation,
}

impl OperationRequest {
    /// Rejects version skew or malformed bounded arguments.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(
            self.protocol_version,
            PROTOCOL_VERSION | INSTALLER_PROTOCOL_VERSION
        ) {
            return Err("unsupported bridge protocol version");
        }
        if matches!(&self.operation, Operation::InstallApprovedPackage { .. })
            && self.protocol_version != INSTALLER_PROTOCOL_VERSION
        {
            return Err("package installation requires bridge protocol version 4");
        }
        self.operation.validate()
    }
}

/// Reconciles an accepted or uncertain operation without issuing it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationStatusRequest {
    pub protocol_version: u32,
    pub operation_id: OperationId,
}

impl OperationStatusRequest {
    /// Rejects protocol skew before looking up the stored receipt.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(
            self.protocol_version,
            PROTOCOL_VERSION | INSTALLER_PROTOCOL_VERSION
        ) {
            return Err("unsupported bridge protocol version");
        }
        Ok(())
    }
}

/// Durable execution state returned for an operation ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Accepted,
    Running,
    Succeeded,
    Failed,
    Unavailable,
    Unknown,
}

/// Minimal result sufficient for safe reconciliation; app policy owns retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReceipt {
    pub protocol_version: u32,
    pub operation_id: OperationId,
    pub state: OperationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl OperationReceipt {
    /// Validates correlation and bounded user-facing detail.
    pub fn validate_for(&self, expected_id: &OperationId) -> Result<(), &'static str> {
        if !matches!(
            self.protocol_version,
            PROTOCOL_VERSION | INSTALLER_PROTOCOL_VERSION
        ) {
            return Err("unsupported bridge protocol version");
        }
        if &self.operation_id != expected_id {
            return Err("operation receipt identity mismatch");
        }
        if self
            .message
            .as_ref()
            .is_some_and(|message| message.len() > 4096)
        {
            return Err("operation receipt message exceeds the limit");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Capability, CapabilityReport, Operation, OperationId, OperationReceipt, OperationRequest,
        OperationState, OperationStatusRequest, PairingRequest, PairingStatus,
        INSTALLER_PROTOCOL_VERSION, PROTOCOL_VERSION,
    };

    #[test]
    fn capability_names_round_trip() {
        for capability in Capability::all() {
            assert_eq!(Capability::parse(capability.as_str()), Some(*capability));
        }
        assert_eq!(Capability::parse("not_a_capability"), None);
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
            capabilities: vec![],
        };
        assert!(
            !report.offers(Capability::WifiNetworkChange),
            "a capability the bridge does not advertise is unavailable"
        );
    }

    #[test]
    fn wire_types_round_trip_through_json() {
        for protocol_version in [PROTOCOL_VERSION, INSTALLER_PROTOCOL_VERSION] {
            let request = PairingRequest {
                bundle_identifier: "com.astronlab.scriptd".to_string(),
                protocol_version,
            };
            let encoded = serde_json::to_string(&request).expect("encode pairing request");
            let decoded: PairingRequest =
                serde_json::from_str(&encoded).expect("decode pairing request");
            assert_eq!(decoded, request);
        }

        let status = PairingStatus {
            protocol_version: INSTALLER_PROTOCOL_VERSION,
            bundle_identifier: "com.astronlab.scriptd".to_string(),
            active: true,
        };
        let encoded = serde_json::to_string(&status).expect("encode pairing status");
        let decoded: PairingStatus = serde_json::from_str(&encoded).expect("decode pairing status");
        assert_eq!(decoded, status);
    }

    #[test]
    fn pairing_request_cannot_claim_a_signing_identity() {
        let forged = r#"{
            "bundle_identifier":"com.astronlab.scriptd",
            "protocol_version":3,
            "signing_identity":"CertificateSHA256:forged"
        }"#;
        assert!(
            serde_json::from_str::<PairingRequest>(forged).is_err(),
            "the bridge derives the signer from the authenticated peer"
        );
    }

    #[test]
    fn operation_requests_are_versioned_and_correlated() {
        let request = OperationRequest {
            protocol_version: PROTOCOL_VERSION,
            operation_id: OperationId::new("cpu:trigger-1").expect("valid operation id"),
            operation: Operation::SetWifiNetwork {
                ssid: "Office".into(),
            },
        };
        request.validate().expect("valid typed operation");
        let encoded = serde_json::to_string(&request).expect("encode operation");
        let decoded: OperationRequest = serde_json::from_str(&encoded).expect("decode operation");
        assert_eq!(decoded, request);
        assert!(!encoded.contains("command"));
        assert!(!encoded.contains("executable_path"));
    }

    #[test]
    fn operation_requests_reject_invalid_ids_arguments_and_versions() {
        assert!(OperationId::new("../tmp/unsafe").is_err());
        assert!(OperationId::new("x".repeat(129)).is_err());
        let request = OperationRequest {
            protocol_version: INSTALLER_PROTOCOL_VERSION + 1,
            operation_id: OperationId::new("wifi-1").expect("valid operation id"),
            operation: Operation::SetWifiNetwork {
                ssid: "Office".into(),
            },
        };
        assert_eq!(
            request.validate(),
            Err("unsupported bridge protocol version")
        );
        let bad_network = Operation::SetWifiNetwork { ssid: "\n".into() };
        assert!(bad_network.validate().is_err());
        let oversized_network = Operation::SetWifiNetwork {
            ssid: "x".repeat(33),
        };
        assert!(oversized_network.validate().is_err());
    }

    #[test]
    fn approved_package_install_requires_v4_and_has_bounded_arguments() {
        let request = OperationRequest {
            protocol_version: INSTALLER_PROTOCOL_VERSION,
            operation_id: OperationId::new("brew:pkg:job-1").expect("valid operation id"),
            operation: Operation::InstallApprovedPackage {
                package_identifier: "com.vendor.product.pkg".into(),
                package_path: "/Users/test/Downloads/Product.pkg".into(),
            },
        };
        request.validate().expect("valid installer request");
        assert_eq!(
            request.operation.capability(),
            Capability::InstallerPackageV1
        );

        let legacy = OperationRequest {
            protocol_version: PROTOCOL_VERSION,
            ..request.clone()
        };
        assert_eq!(
            legacy.validate(),
            Err("package installation requires bridge protocol version 4")
        );
        let unsafe_path = Operation::InstallApprovedPackage {
            package_identifier: "com.vendor.product".into(),
            package_path: "relative.pkg".into(),
        };
        assert!(unsafe_path.validate().is_err());
    }

    #[test]
    fn receipts_require_the_same_id_and_bounded_detail() {
        let id = OperationId::new("cpu-1").expect("valid operation id");
        let receipt = OperationReceipt {
            protocol_version: PROTOCOL_VERSION,
            operation_id: id.clone(),
            state: OperationState::Unknown,
            message: Some("response lost".into()),
        };
        receipt.validate_for(&id).expect("matching receipt");
        let other = OperationId::new("cpu-2").expect("valid operation id");
        assert_eq!(
            receipt.validate_for(&other),
            Err("operation receipt identity mismatch")
        );
        let oversized = OperationReceipt {
            message: Some("x".repeat(4097)),
            ..receipt
        };
        assert_eq!(
            oversized.validate_for(&id),
            Err("operation receipt message exceeds the limit")
        );
    }

    #[test]
    fn status_queries_reconcile_only_by_the_original_operation_id() {
        let id = OperationId::new("router:job.7").expect("valid operation id");
        let query = OperationStatusRequest {
            protocol_version: PROTOCOL_VERSION,
            operation_id: id.clone(),
        };
        query.validate().expect("compatible status query");
        let encoded = serde_json::to_string(&query).expect("encode status query");
        let decoded: OperationStatusRequest =
            serde_json::from_str(&encoded).expect("decode status query");
        assert_eq!(decoded.operation_id, id);
    }

    #[test]
    fn operation_wire_rejects_unrecognized_general_command_fields() {
        let raw = r#"{
            "protocol_version":3,
            "operation_id":"cpu-1",
            "operation":{"kind":"terminate_process","pid":42,"bundle_identifier":"com.example.editor","command":"/bin/sh"}
        }"#;
        assert!(
            serde_json::from_str::<OperationRequest>(raw).is_err(),
            "the bridge protocol must not silently accept general command execution"
        );
    }
}
