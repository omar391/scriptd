#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::credentials;
use crate::modules::{ModuleContext, ModuleHealth, ModuleStatus};

#[derive(Debug, Clone)]
pub struct EnvMap {
    values: HashMap<String, String>,
}

fn parse_env_u64(raw: Option<&str>, fallback: u64) -> u64 {
    raw.and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn parse_env_f64(raw: Option<&str>, fallback: f64) -> f64 {
    raw.and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        .unwrap_or(fallback)
}

impl EnvMap {
    fn read() -> Self {
        Self {
            values: std::env::vars().collect(),
        }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
}

impl Default for EnvMap {
    fn default() -> Self {
        Self::read()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub ssid: String,
    pub band: String,
    pub rssi: i64,
    pub channel: String,
    pub security: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WifiSignal {
    channel: i64,
    rssi: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MwifiConfig {
    #[serde(rename = "min_dwell")]
    pub min_dwell_seconds: u64,
    pub ping_target: String,
    pub ping_count: u64,
    #[serde(rename = "ping_timeout")]
    pub ping_timeout_seconds: u64,
    pub ping_high_latency_ms: u64,
    pub health_failure_switch_runs: u64,
    #[serde(rename = "band_bonus_2g")]
    pub band_bonus_2g: f64,
    #[serde(rename = "band_bonus_5g")]
    pub band_bonus_5g: f64,
    #[serde(rename = "band_bonus_6g")]
    pub band_bonus_6g: f64,
    #[serde(rename = "preference_top_bonus")]
    pub preference_top_bonus: f64,
    #[serde(rename = "preference_rank_decay")]
    pub preference_rank_decay: f64,
    #[serde(rename = "current_sticky_bonus")]
    pub current_sticky_bonus: f64,
    #[serde(rename = "rssi_offset")]
    pub rssi_offset: f64,
    #[serde(rename = "min_switch_score_delta")]
    pub min_switch_score_delta: f64,
    #[serde(default)]
    pub ssids: Vec<String>,
    #[serde(default)]
    pub state_file: String,
    #[serde(default)]
    pub config_path: String,
}

impl Default for MwifiConfig {
    fn default() -> Self {
        Self {
            min_dwell_seconds: 180,
            ping_target: "1.1.1.1".to_string(),
            ping_count: 3,
            ping_timeout_seconds: 1,
            ping_high_latency_ms: 250,
            health_failure_switch_runs: 2,
            band_bonus_2g: 0.0,
            band_bonus_5g: 35.0,
            band_bonus_6g: 50.0,
            preference_top_bonus: 30.0,
            preference_rank_decay: 5.0,
            current_sticky_bonus: 25.0,
            rssi_offset: 100.0,
            min_switch_score_delta: 10.0,
            ssids: Vec::new(),
            state_file: String::new(),
            config_path: String::new(),
        }
    }
}

#[allow(dead_code)]
pub fn resolve_mwifi_config(raw: &MwifiConfig, env: &EnvMap) -> MwifiConfig {
    let env_ssids = env
        .get("MWIFI_SSIDS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let state_file = env
        .get("MWIFI_STATE_FILE")
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            if raw.state_file.is_empty() {
                let home = crate::paths::home_dir();
                home.join(".local/share/mwifi/state.txt")
                    .to_string_lossy()
                    .to_string()
            } else {
                raw.state_file.clone()
            }
        });

    let config_path = env
        .get("MWIFI_CONFIG_PATH")
        .map(ToString::to_string)
        .unwrap_or_else(|| raw.config_path.clone());

    MwifiConfig {
        min_dwell_seconds: parse_env_u64(env.get("MWIFI_MIN_DWELL"), raw.min_dwell_seconds),
        ping_target: env
            .get("MWIFI_PING_TARGET")
            .unwrap_or(raw.ping_target.as_str())
            .to_string(),
        ping_count: parse_env_u64(env.get("MWIFI_PING_COUNT"), raw.ping_count),
        ping_timeout_seconds: parse_env_u64(
            env.get("MWIFI_PING_TIMEOUT"),
            raw.ping_timeout_seconds,
        ),
        ping_high_latency_ms: parse_env_u64(
            env.get("MWIFI_PING_HIGH_LATENCY_MS"),
            raw.ping_high_latency_ms,
        ),
        health_failure_switch_runs: parse_env_u64(
            env.get("MWIFI_HEALTH_FAILURE_SWITCH_RUNS"),
            raw.health_failure_switch_runs,
        ),
        band_bonus_2g: raw.band_bonus_2g,
        band_bonus_5g: raw.band_bonus_5g,
        band_bonus_6g: raw.band_bonus_6g,
        preference_top_bonus: raw.preference_top_bonus,
        preference_rank_decay: raw.preference_rank_decay,
        current_sticky_bonus: raw.current_sticky_bonus,
        rssi_offset: raw.rssi_offset,
        min_switch_score_delta: parse_env_f64(
            env.get("MWIFI_MIN_SWITCH_SCORE_DELTA"),
            raw.min_switch_score_delta,
        ),
        ssids: if env_ssids.is_empty() {
            raw.ssids.clone()
        } else {
            env_ssids
        },
        state_file,
        config_path,
    }
}

#[derive(Debug, Clone)]
struct PersistedWifiState {
    last_ssid: String,
    last_connected_at: Option<String>,
    last_switch_at: Option<String>,
    health_failure_streak: u64,
    last_health: Option<StoredHealth>,
    join_failures: HashMap<String, StoredJoinFailure>,
}

#[derive(Debug, Clone)]
struct StoredHealth {
    packet_loss_percent: f64,
    avg_latency_ms: Option<f64>,
}

#[derive(Debug, Clone)]
struct StoredJoinFailure {
    failed_at: String,
    message: String,
}

#[derive(Debug, Default)]
struct MwifiState {
    current_ssid: String,
    last_switch_at: Option<String>,
    last_decision: Option<String>,
    last_run_at: Option<String>,
    loop_count: u64,
    last_error: Option<String>,
}

static STATE: once_cell::sync::Lazy<std::sync::Mutex<MwifiState>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(MwifiState::default()));

#[derive(Debug, Clone)]
pub struct PingHealth {
    pub packet_loss_percent: f64,
    pub avg_latency_ms: Option<f64>,
    pub healthy: bool,
    pub severe: bool,
    pub penalty: f64,
}

#[derive(Debug, Clone)]
pub struct CandidateScore {
    pub network: Network,
    pub rank: usize,
    pub rssi_score: f64,
    pub band_bonus: f64,
    pub preference_bonus: f64,
    pub sticky_bonus: f64,
    pub health_penalty: f64,
    pub join_failure_penalty: f64,
    pub total_score: f64,
}

const JOIN_FAILURE_COOLDOWN_SECONDS: i64 = 15 * 60;
const JOIN_FAILURE_SCORE_PENALTY: f64 = 1_000.0;

#[derive(Debug, Deserialize)]
struct SwiftScanRecord {
    ssid: String,
    rssi: i64,
    channel: String,
    #[serde(default)]
    summary: Option<String>,
}

fn command_exists(command_name: &str) -> bool {
    Command::new("sh")
        .args(["-lc", &format!("command -v {command_name} >/dev/null 2>&1")])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_swift(code: &str) -> anyhow::Result<String> {
    let output = Command::new("swift").args(["-e", code]).output()?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn read_state(state_file: &str) -> PersistedWifiState {
    let Ok(raw) = fs::read_to_string(state_file) else {
        return PersistedWifiState {
            last_ssid: String::new(),
            last_connected_at: None,
            last_switch_at: None,
            health_failure_streak: 0,
            last_health: None,
            join_failures: HashMap::new(),
        };
    };

    let json = serde_json::from_str::<serde_json::Value>(&raw).ok();
    if let Some(value) = json {
        let join_failures = value
            .get("joinFailures")
            .and_then(|entry| entry.as_object())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(ssid, entry)| {
                        let failed_at = entry.get("failedAt")?.as_str()?.to_string();
                        let message = entry
                            .get("message")
                            .and_then(|value| value.as_str())
                            .unwrap_or("")
                            .to_string();
                        Some((ssid.clone(), StoredJoinFailure { failed_at, message }))
                    })
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        return PersistedWifiState {
            last_ssid: value
                .get("lastSsid")
                .and_then(|entry| entry.as_str())
                .unwrap_or("")
                .to_string(),
            last_connected_at: value
                .get("lastConnectedAt")
                .and_then(|entry| entry.as_str())
                .map(str::to_string),
            last_switch_at: value
                .get("lastSwitchAt")
                .and_then(|entry| entry.as_str())
                .map(str::to_string),
            health_failure_streak: value
                .get("healthFailureStreak")
                .and_then(|entry| entry.as_u64())
                .unwrap_or(0),
            last_health: value.get("lastHealth").map(|entry| StoredHealth {
                packet_loss_percent: entry
                    .get("packetLossPercent")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(100.0),
                avg_latency_ms: entry.get("avgLatencyMs").and_then(|v| v.as_f64()),
            }),
            join_failures,
        };
    }

    PersistedWifiState {
        last_ssid: String::new(),
        last_connected_at: None,
        last_switch_at: None,
        health_failure_streak: 0,
        last_health: None,
        join_failures: HashMap::new(),
    }
}

fn write_state(path: &str, state: &PersistedWifiState) {
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut data = serde_json::Map::new();
    data.insert(
        "lastSsid".to_string(),
        serde_json::Value::String(state.last_ssid.clone()),
    );
    if let Some(last_connected_at) = &state.last_connected_at {
        data.insert(
            "lastConnectedAt".to_string(),
            serde_json::Value::String(last_connected_at.clone()),
        );
    }
    if let Some(last_switch_at) = &state.last_switch_at {
        data.insert(
            "lastSwitchAt".to_string(),
            serde_json::Value::String(last_switch_at.clone()),
        );
    }
    data.insert(
        "healthFailureStreak".to_string(),
        serde_json::Value::Number(serde_json::Number::from(state.health_failure_streak)),
    );
    if let Some(health) = &state.last_health {
        let mut health_value = serde_json::Map::new();
        let loss = serde_json::Number::from_f64(health.packet_loss_percent)
            .or_else(|| serde_json::Number::from_f64(100.0))
            .unwrap_or_else(|| serde_json::Number::from(100));
        health_value.insert(
            "packetLossPercent".to_string(),
            serde_json::Value::Number(loss),
        );
        if let Some(latency) = health.avg_latency_ms {
            let latency = serde_json::Number::from_f64(latency)
                .unwrap_or_else(|| serde_json::Number::from(0));
            health_value.insert(
                "avgLatencyMs".to_string(),
                serde_json::Value::Number(latency),
            );
        }
        data.insert(
            "lastHealth".to_string(),
            serde_json::Value::Object(health_value),
        );
    }
    if !state.join_failures.is_empty() {
        let mut failures = serde_json::Map::new();
        for (ssid, failure) in &state.join_failures {
            let mut failure_value = serde_json::Map::new();
            failure_value.insert(
                "failedAt".to_string(),
                serde_json::Value::String(failure.failed_at.clone()),
            );
            failure_value.insert(
                "message".to_string(),
                serde_json::Value::String(failure.message.clone()),
            );
            failures.insert(ssid.clone(), serde_json::Value::Object(failure_value));
        }
        data.insert(
            "joinFailures".to_string(),
            serde_json::Value::Object(failures),
        );
    }
    let _ = fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::Value::Object(data)).unwrap_or_default(),
    );
}

fn prune_join_failures(
    failures: &HashMap<String, StoredJoinFailure>,
    now: DateTime<Utc>,
) -> HashMap<String, StoredJoinFailure> {
    failures
        .iter()
        .filter_map(|(ssid, failure)| {
            let failed_at = DateTime::parse_from_rfc3339(&failure.failed_at)
                .ok()?
                .with_timezone(&Utc);
            ((now - failed_at).num_seconds() < JOIN_FAILURE_COOLDOWN_SECONDS)
                .then_some((ssid.clone(), failure.clone()))
        })
        .collect()
}

fn join_failure_penalty(
    ssid: &str,
    failures: &HashMap<String, StoredJoinFailure>,
    now: DateTime<Utc>,
) -> f64 {
    let Some(failure) = failures.get(ssid) else {
        return 0.0;
    };
    let Ok(failed_at) = DateTime::parse_from_rfc3339(&failure.failed_at) else {
        return 0.0;
    };
    if (now - failed_at.with_timezone(&Utc)).num_seconds() < JOIN_FAILURE_COOLDOWN_SECONDS {
        JOIN_FAILURE_SCORE_PENALTY
    } else {
        0.0
    }
}

fn parse_wifi_device() -> anyhow::Result<String> {
    let output = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("networksetup listallhardwareports failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let lines = text.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "Hardware Port: Wi-Fi" {
            for offset in 1..4 {
                if index + offset >= lines.len() {
                    break;
                }
                let candidate = lines[index + offset].trim();
                if let Some(rest) = candidate.strip_prefix("Device: ") {
                    return Ok(rest.to_string());
                }
            }
        }
    }

    if command_exists("swift") {
        let output = run_swift(
            r#"
import Foundation
import CoreWLAN

if let iface = CWWiFiClient.shared().interface(), let name = iface.interfaceName {
    print(name)
}
"#,
        )?;
        if !output.is_empty() {
            return Ok(output);
        }
    }

    anyhow::bail!("Could not detect wifi device")
}

fn parse_networksetup_current_ssid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        ["Current Wi-Fi Network:", "Current AirPort Network:"]
            .iter()
            .find_map(|prefix| {
                trimmed
                    .strip_prefix(prefix)
                    .map(str::trim)
                    .filter(|value| is_usable_current_ssid(value))
                    .map(str::to_string)
            })
    })
}

fn is_usable_current_ssid(value: &str) -> bool {
    let normalized = value.trim();
    !normalized.is_empty()
        && !matches!(
            normalized.to_ascii_lowercase().as_str(),
            "<redacted>" | "redacted" | "unknown"
        )
}

fn parse_ipconfig_current_ssid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("SSID :")
            .map(str::trim)
            .filter(|value| is_usable_current_ssid(value))
            .map(str::to_string)
    })
}

fn parse_wifi_signal_output(output: &str) -> Option<WifiSignal> {
    output.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let channel = parts.next()?.parse::<i64>().ok()?;
        let rssi = parts.next()?.parse::<i64>().ok()?;
        Some(WifiSignal { channel, rssi })
    })
}

fn current_wifi_signal() -> anyhow::Result<Option<WifiSignal>> {
    if !command_exists("swift") {
        return Ok(None);
    }

    let output = run_swift(
        r#"
import Foundation
import CoreWLAN

if let iface = CWWiFiClient.shared().interface(), let channel = iface.wlanChannel() {
    print("\(channel.channelNumber)\t\(iface.rssiValue())")
}
"#,
    )?;
    Ok(parse_wifi_signal_output(&output))
}

fn current_ssid(device: &str) -> anyhow::Result<String> {
    let output = Command::new("networksetup")
        .args(["-getairportnetwork", device])
        .output()?;
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(current) = parse_networksetup_current_ssid(&text) {
            return Ok(current);
        }
    }

    let output = Command::new("ipconfig")
        .args(["getsummary", device])
        .output()?;
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(current) = parse_ipconfig_current_ssid(&text) {
            return Ok(current);
        }
    }

    if command_exists("swift") {
        let output = run_swift(
            r#"
import Foundation
import CoreWLAN

if let iface = CWWiFiClient.shared().interface(), let ssid = iface.ssid() {
    print(ssid)
}
"#,
        )?;
        if !output.is_empty() {
            return Ok(output);
        }
    }

    Ok(String::new())
}

fn parse_primary_channel(channel: &str) -> Option<i64> {
    let digits = channel
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<i64>().ok()
}

fn infer_current_ssid_from_signal(networks: &[Network], signal: WifiSignal) -> Option<String> {
    let mut matches = networks
        .iter()
        .filter(|network| parse_primary_channel(&network.channel) == Some(signal.channel))
        .filter_map(|network| {
            let diff = (network.rssi - signal.rssi).abs();
            (diff <= 12).then_some((network.ssid.clone(), diff))
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|(_, diff)| *diff);

    match matches.as_slice() {
        [(ssid, _)] => Some(ssid.clone()),
        [(ssid, best_diff), (_, next_diff), ..] if best_diff < next_diff => Some(ssid.clone()),
        _ => None,
    }
}

fn parse_airport_output(output: &str, allowed: &[String]) -> Vec<Network> {
    let mut out = Vec::new();
    for line in output.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
        let Some(bssid_index) = tokens.iter().position(|token| {
            let parts = token.split(':').collect::<Vec<_>>();
            parts.len() == 6
                && parts
                    .iter()
                    .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
        }) else {
            continue;
        };
        if bssid_index == 0 {
            continue;
        }

        let ssid = tokens[..bssid_index].join(" ");
        if ssid.is_empty() {
            continue;
        }
        if !allowed.is_empty() && !allowed.iter().any(|value| value == &ssid) {
            continue;
        }

        let parts = &tokens[bssid_index..];
        if parts.len() < 4 {
            continue;
        }

        let rssi = parts
            .get(1)
            .copied()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(-999);
        let channel = parts.get(2).copied().unwrap_or("1").to_string();
        let security = if parts.len() >= 6 {
            parts[5..].join(" ")
        } else if parts.len() >= 4 {
            parts[3..].join(" ")
        } else {
            String::new()
        };
        let channel_num = channel.parse::<u32>().unwrap_or(0);
        let band = if channel_num > 165 {
            "6g"
        } else if channel_num >= 36 {
            "5g"
        } else {
            "2g"
        };
        out.push(Network {
            ssid,
            band: band.to_string(),
            rssi,
            channel,
            security: if security.is_empty() {
                "unknown".to_string()
            } else {
                security
            },
            ping_ms: None,
        });
    }
    out
}

fn parse_security(summary: &str) -> String {
    let marker = "security=";
    let Some(start) = summary.find(marker) else {
        return "unknown".to_string();
    };
    let rest = &summary[start + marker.len()..];
    let end = rest.find([',', ']']).unwrap_or(rest.len());
    let parsed = rest[..end].trim();
    if parsed.is_empty() {
        "unknown".to_string()
    } else {
        parsed.to_string()
    }
}

fn parse_swift_wifi_scan_output(output: &str) -> Vec<Network> {
    let Ok(parsed) = serde_json::from_str::<Vec<SwiftScanRecord>>(output) else {
        return Vec::new();
    };

    parsed
        .into_iter()
        .filter(|item| !item.ssid.trim().is_empty())
        .map(|item| {
            let channel_number = item
                .channel
                .chars()
                .filter(|ch| ch.is_ascii_digit())
                .collect::<String>()
                .parse::<u32>()
                .unwrap_or(0);
            let band = if channel_number > 165 {
                "6g"
            } else if channel_number >= 36 {
                "5g"
            } else {
                "2g"
            };

            Network {
                ssid: item.ssid.trim().to_string(),
                band: band.to_string(),
                rssi: item.rssi,
                channel: item.channel,
                security: item
                    .summary
                    .as_deref()
                    .map(parse_security)
                    .unwrap_or_else(|| "unknown".to_string()),
                ping_ms: None,
            }
        })
        .collect()
}

fn scan_wifi_via_swift(allowed: &[String]) -> anyhow::Result<Vec<Network>> {
    if !command_exists("swift") {
        anyhow::bail!("swift is not available for Wi-Fi scanning");
    }

    let output = run_swift(
        r#"
import Foundation
import CoreWLAN

let client = CWWiFiClient.shared()
guard let iface = client.interface() else {
    throw NSError(domain: "scriptd", code: 1, userInfo: [NSLocalizedDescriptionKey: "No Wi-Fi interface available"])
}

let networks = try iface.scanForNetworks(withSSID: nil)
let rows: [[String: Any]] = networks.compactMap { network in
    guard let ssid = network.ssid, !ssid.isEmpty else {
        return nil
    }

    return [
        "ssid": ssid,
        "rssi": network.rssiValue,
        "channel": String(network.wlanChannel?.channelNumber ?? 0),
        "summary": String(describing: network),
    ]
}

let data = try JSONSerialization.data(withJSONObject: rows, options: [])
print(String(data: data, encoding: .utf8) ?? "[]")
"#,
    )?;

    let parsed = parse_swift_wifi_scan_output(&output);
    Ok(parsed
        .into_iter()
        .filter(|network| allowed.is_empty() || allowed.iter().any(|value| value == &network.ssid))
        .collect())
}

#[cfg(feature = "corewlan")]
#[allow(deprecated)]
fn scan_corewlan_networks(allowed: &[String]) -> Vec<Network> {
    use objc2_core_wlan::{CWChannelBand, CWInterface};

    let mut out = Vec::new();
    unsafe {
        let interface = CWInterface::interface();
        let results = interface
            .scanForNetworksWithSSID_error(None)
            .ok()
            .or_else(|| interface.cachedScanResults());
        let Some(results) = results else {
            return out;
        };

        for network in results.iter() {
            let Some(ssid) = network.ssid().map(|value| value.to_string()) else {
                continue;
            };
            if !allowed.is_empty() && !allowed.iter().any(|value| value == &ssid) {
                continue;
            }

            let (channel, band) = network
                .wlanChannel()
                .map(|channel| {
                    let channel_number = channel.channelNumber().to_string();
                    let band = match channel.channelBand() {
                        CWChannelBand::Band6GHz => "6g",
                        CWChannelBand::Band5GHz => "5g",
                        CWChannelBand::Band2GHz => "2g",
                        _ => "unknown",
                    };
                    (channel_number, band.to_string())
                })
                .unwrap_or_else(|| ("0".to_string(), "unknown".to_string()));

            out.push(Network {
                ssid,
                band,
                rssi: network.rssiValue() as i64,
                channel,
                security: "CoreWLAN".to_string(),
                ping_ms: None,
            });
        }
    }
    out
}

#[cfg(not(feature = "corewlan"))]
fn scan_corewlan_networks(_allowed: &[String]) -> Vec<Network> {
    Vec::new()
}

fn scan_networks(allowed: &[String]) -> Vec<Network> {
    if let Ok(output) = std::env::var("SCRIPTD_MWIFI_SCAN_OUTPUT") {
        return parse_airport_output(&output, allowed);
    }

    let corewlan = scan_corewlan_networks(allowed);
    if !corewlan.is_empty() {
        return corewlan;
    }

    let output = Command::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .args(["-s"])
    .output()
    .ok()
    .and_then(|value| {
        if value.status.success() {
            Some(String::from_utf8_lossy(&value.stdout).to_string())
        } else {
            None
        }
    })
    .or_else(|| {
        std::env::var("SCRIPTD_MWIFI_SCAN_FALLBACK")
            .ok()
            .map(|_| String::new())
    });
    let output = output.unwrap_or_default();
    let parsed = if output.is_empty() {
        Vec::new()
    } else {
        parse_airport_output(&output, allowed)
    };
    if !parsed.is_empty() {
        return parsed;
    }

    scan_wifi_via_swift(allowed).unwrap_or_default()
}

fn command_time_ms(output: &str) -> Option<f64> {
    if output.is_empty() {
        return None;
    }

    for line in output.lines() {
        if line.contains("round-trip") && line.contains(" = ") && line.contains(" ms") {
            let metrics = line.split(" = ").nth(1)?.trim();
            let mut parts = metrics.split('/');
            let _min = parts.next()?;
            let avg = parts.next()?.trim();
            return avg.parse::<f64>().ok().map(|value| value.round());
        }
    }

    None
}

fn parse_ping_health_output(
    output: &str,
    ping_high_latency_ms: u64,
    prior_streak: u64,
) -> PingHealth {
    let packet_loss_percent = output
        .split_whitespace()
        .find_map(|token| {
            if token.ends_with('%') {
                token.trim_end_matches('%').parse::<f64>().ok()
            } else {
                None
            }
        })
        .unwrap_or(100.0);
    let avg_latency_ms = command_time_ms(output);
    let degraded = packet_loss_percent > 0.0
        || avg_latency_ms.is_some_and(|value| value > ping_high_latency_ms as f64);
    let severe = packet_loss_percent >= 100.0;
    let mut penalty = if severe {
        45.0
    } else if degraded {
        15.0
    } else {
        0.0
    };
    if prior_streak >= 1 && degraded {
        penalty += 25.0;
    }

    PingHealth {
        packet_loss_percent,
        avg_latency_ms,
        healthy: !degraded,
        severe,
        penalty,
    }
}

pub fn ping_health(target: &str, config: &MwifiConfig, prior_streak: u64) -> PingHealth {
    let args = [
        "-c".to_string(),
        format!("{}", config.ping_count),
        "-W".to_string(),
        (config.ping_timeout_seconds * 1000).to_string(),
        target.to_string(),
    ];
    let result = Command::new("ping").args(&args).output().ok();
    let output = result
        .as_ref()
        .map(|value| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&value.stdout),
                String::from_utf8_lossy(&value.stderr)
            )
        })
        .unwrap_or_default();
    parse_ping_health_output(&output, config.ping_high_latency_ms, prior_streak)
}

pub fn priority_for(ssid: &str, preference: &[String]) -> usize {
    preference
        .iter()
        .position(|value| value == ssid)
        .unwrap_or(usize::MAX)
}

fn score_band(network: &Network, config: &MwifiConfig) -> f64 {
    if network.band == "6g" {
        config.band_bonus_6g
    } else if network.band == "5g" {
        config.band_bonus_5g
    } else {
        config.band_bonus_2g
    }
}

fn preference_bonus(rank: usize, config: &MwifiConfig) -> f64 {
    if rank == usize::MAX {
        0.0
    } else {
        (config.preference_top_bonus - (rank as f64 * config.preference_rank_decay)).max(0.0)
    }
}

pub fn build_candidate_score(
    network: &Network,
    config: &MwifiConfig,
    priority: &[String],
    current_ssid: &str,
    current_health_penalty: f64,
) -> CandidateScore {
    let rank = priority_for(&network.ssid, priority);
    let rssi_score = (network.rssi as f64 + config.rssi_offset).clamp(0.0, 100.0);
    let band_bonus = score_band(network, config);
    let preference = preference_bonus(rank, config);
    let sticky = if network.ssid == current_ssid {
        config.current_sticky_bonus
    } else {
        0.0
    };
    let health_penalty = if network.ssid == current_ssid {
        current_health_penalty
    } else {
        0.0
    };

    build_candidate_score_with_join_failure_penalty(
        network,
        rank,
        rssi_score,
        band_bonus,
        preference,
        sticky,
        health_penalty,
        0.0,
    )
}

fn build_candidate_score_with_join_failure_penalty(
    network: &Network,
    rank: usize,
    rssi_score: f64,
    band_bonus: f64,
    preference: f64,
    sticky: f64,
    health_penalty: f64,
    join_failure_penalty: f64,
) -> CandidateScore {
    CandidateScore {
        network: network.clone(),
        rank,
        rssi_score,
        band_bonus,
        preference_bonus: preference,
        sticky_bonus: sticky,
        health_penalty,
        join_failure_penalty,
        total_score: rssi_score + band_bonus + preference + sticky
            - health_penalty
            - join_failure_penalty,
    }
}

fn dedupe_networks(
    networks: &[Network],
    config: &MwifiConfig,
    priority: &[String],
) -> Vec<Network> {
    let mut best = HashMap::<String, CandidateScore>::new();
    for network in networks {
        let score = build_candidate_score(network, config, priority, "", 0.0);
        let existing = best.get(&network.ssid);
        if existing.is_none_or(|entry| score.total_score > entry.total_score) {
            best.insert(network.ssid.clone(), score);
        }
    }
    best.into_values().map(|entry| entry.network).collect()
}

fn score_network(network: &Network, config: &MwifiConfig) -> f64 {
    score_band(network, config) + (network.rssi as f64 + config.rssi_offset).clamp(0.0, 100.0)
}

pub fn describe_candidates(candidates: &[CandidateScore]) -> String {
    if candidates.is_empty() {
        return "none".to_string();
    }
    let mut ranked = candidates.to_vec();
    ranked.sort_by(|left, right| {
        switch_score(right)
            .total_cmp(&switch_score(left))
            .then(left.rank.cmp(&right.rank))
    });
    ranked
        .iter()
        .map(|candidate| {
            format!(
                "{}(band={}, rssi={}, pref={}, bandBonus={}, sticky={}, healthPenalty={}, joinPenalty={}, total={}, switchScore={})",
                candidate.network.ssid,
                candidate.network.band,
                candidate.network.rssi,
                format_metric(candidate.preference_bonus),
                format_metric(candidate.band_bonus),
                format_metric(candidate.sticky_bonus),
                format_metric(candidate.health_penalty),
                format_metric(candidate.join_failure_penalty),
                format_metric(candidate.total_score),
                format_metric(switch_score(candidate))
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn switch_score(candidate: &CandidateScore) -> f64 {
    candidate.total_score - candidate.sticky_bonus
}

pub fn effective_current_ssid(current: &str, _persisted: &str, _networks: &[Network]) -> String {
    if !current.is_empty() {
        return current.to_string();
    }
    String::new()
}

pub fn decide_wifi_switch(
    current: &str,
    candidates: &[CandidateScore],
    config: &MwifiConfig,
    dwell_satisfied: bool,
    health_failure_streak: u64,
) -> String {
    let ranked = {
        let mut ranked = candidates.to_vec();
        ranked.sort_by(|left, right| {
            switch_score(right)
                .total_cmp(&switch_score(left))
                .then(right.rank.cmp(&left.rank))
        });
        ranked
    };
    let best = ranked.first();
    if best.is_none() {
        return format!("stay:{current}");
    }
    if current.is_empty() {
        return "stay:".to_string();
    }
    let best = best.expect("candidate exists");
    let current_candidate = ranked
        .iter()
        .find(|candidate| candidate.network.ssid == current)
        .or(Some(best));
    let current = current_candidate
        .expect("current candidate should exist")
        .clone();
    let delta = switch_score(best) - switch_score(&current);
    if best.network.ssid == current.network.ssid {
        return format!("stay:{}", current.network.ssid);
    }
    if !dwell_satisfied {
        return format!("hold:{}", current.network.ssid);
    }
    if health_failure_streak >= config.health_failure_switch_runs && delta >= 10.0 {
        return format!("switch:{}:{}", current.network.ssid, best.network.ssid);
    }
    if delta >= config.min_switch_score_delta {
        return format!("switch:{}:{}", current.network.ssid, best.network.ssid);
    }
    format!("stay:{}", current.network.ssid)
}

fn format_metric(value: f64) -> String {
    let mut rendered = format!("{value:.3}");
    while rendered.contains('.') && rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.pop();
    }
    rendered
}

fn build_decision_reason(
    decision: &str,
    current_ssid: &str,
    candidates: &[CandidateScore],
    config: &MwifiConfig,
    health_failure_streak: u64,
) -> String {
    let mut ranked = candidates.to_vec();
    ranked.sort_by(|left, right| {
        switch_score(right)
            .total_cmp(&switch_score(left))
            .then(left.rank.cmp(&right.rank))
    });

    let current_label = if current_ssid.is_empty() {
        "current network"
    } else {
        current_ssid
    };
    let Some(best) = ranked.first() else {
        return "no eligible networks found".to_string();
    };
    let current = ranked
        .iter()
        .find(|candidate| candidate.network.ssid == current_ssid);
    let delta = current
        .map(|candidate| switch_score(best) - switch_score(candidate))
        .unwrap_or(0.0);

    if let Some(ssid) = decision.strip_prefix("hold:") {
        let label = if ssid.is_empty() { current_label } else { ssid };
        return format!("holding {label} until dwell window completes");
    }

    if let Some(rest) = decision.strip_prefix("switch:") {
        let mut parts = rest.splitn(2, ':');
        let _from = parts.next().unwrap_or_default();
        let to = parts.next().unwrap_or_default();
        if health_failure_streak >= config.health_failure_switch_runs && delta >= 10.0 {
            return format!(
                "switching to {to}; repeated health failures and score delta {} >= 10",
                format_metric(delta)
            );
        }
        return format!(
            "switching to {to}; score delta {} >= {}",
            format_metric(delta),
            format_metric(config.min_switch_score_delta)
        );
    }

    if current_ssid.is_empty() {
        return "staying on current network; current SSID unavailable".to_string();
    }

    if best.network.ssid == current_ssid || current.is_none() {
        return format!("staying on {current_label}");
    }

    format!(
        "staying on {current_label}; best switch score delta {} is below required threshold",
        format_metric(delta)
    )
}

fn connect_network(device: &str, ssid: &str) -> anyhow::Result<()> {
    match run_networksetup_join(device, ssid, None)? {
        JoinAttempt::Succeeded => return Ok(()),
        JoinAttempt::Failed(message) => {
            if let Some(password) = find_wifi_password(ssid) {
                match run_networksetup_join(device, ssid, Some(&password))? {
                    JoinAttempt::Succeeded => return Ok(()),
                    JoinAttempt::Failed(password_message) => {
                        anyhow::bail!(
                            "Could not switch Wi-Fi to {ssid}: passwordless join failed: {}; password-backed join failed: {}",
                            password_message_for_error(&message),
                            password_message_for_error(&password_message)
                        );
                    }
                }
            }

            anyhow::bail!("Could not switch Wi-Fi to {ssid}: {message}");
        }
    }
}

enum JoinAttempt {
    Succeeded,
    Failed(String),
}

fn run_networksetup_join(
    device: &str,
    ssid: &str,
    password: Option<&str>,
) -> anyhow::Result<JoinAttempt> {
    let mut command = Command::new("networksetup");
    command.args(["-setairportnetwork", device, ssid]);
    if let Some(password) = password {
        command.arg(password);
    }
    let output = command.output()?;
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        let details = message.trim();
        if details.is_empty() {
            return Ok(JoinAttempt::Failed("networksetup failed".to_string()));
        }
        return Ok(JoinAttempt::Failed(details.to_string()));
    }
    Ok(JoinAttempt::Succeeded)
}

fn find_wifi_password(ssid: &str) -> Option<String> {
    password_from_env(ssid)
        .or_else(|| password_from_scriptd_keychain(ssid))
        .or_else(|| import_system_airport_password(ssid))
}

fn run_password_networksetup_join(device: &str, ssid: &str) -> Option<Result<(), String>> {
    let password = find_wifi_password(ssid)?;
    Some(
        run_networksetup_join(device, ssid, Some(&password))
            .map_err(|error| error.to_string())
            .and_then(|attempt| match attempt {
                JoinAttempt::Succeeded => Ok(()),
                JoinAttempt::Failed(message) => Err(password_message_for_error(&message)),
            }),
    )
}

fn run_sudo_networksetup_join(device: &str, ssid: &str) -> anyhow::Result<JoinAttempt> {
    let admin_password = scriptd_admin_password()
        .map_err(|error| anyhow::anyhow!("scriptd admin password is unavailable: {error}"))?;

    let mut command = Command::new("sudo");
    command
        .args([
            "-S",
            "-p",
            "",
            "networksetup",
            "-setairportnetwork",
            device,
            ssid,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(format!("{admin_password}\n").as_bytes())?;
        let _ = stdin.flush();
    }
    let output = child.wait_with_output()?;
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        let details = message.trim();
        if details.is_empty() {
            return Ok(JoinAttempt::Failed("sudo networksetup failed".to_string()));
        }
        return Ok(JoinAttempt::Failed(details.to_string()));
    }
    Ok(JoinAttempt::Succeeded)
}

fn scriptd_admin_password() -> anyhow::Result<String> {
    credentials::admin_password_or_prompt(Some(credentials::LEGACY_BREW_ADMIN_SERVICE))
}

fn password_message_for_error(message: &str) -> String {
    message.replace('\n', " ")
}

fn scriptd_mwifi_keychain_service(ssid: &str) -> String {
    credentials::scriptd_service("mwifi", ssid)
}

fn legacy_scriptd_wifi_keychain_services(ssid: &str) -> [String; 2] {
    [
        credentials::scriptd_service("better-wifi", ssid),
        credentials::scriptd_service("wifi", ssid),
    ]
}

fn password_from_env(ssid: &str) -> Option<String> {
    let specific_key = format!("MWIFI_PASSWORD_{}", env_key_suffix(ssid));
    std::env::var(&specific_key)
        .ok()
        .or_else(|| std::env::var("MWIFI_PASSWORD").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn password_from_scriptd_keychain(ssid: &str) -> Option<String> {
    let service = scriptd_mwifi_keychain_service(ssid);
    if let Some(password) = credentials::find_generic_password(&service, ssid)
        .ok()
        .flatten()
    {
        return Some(password);
    }

    for legacy_service in legacy_scriptd_wifi_keychain_services(ssid) {
        if let Some(password) = credentials::find_generic_password(&legacy_service, ssid)
            .ok()
            .flatten()
        {
            let _ = store_scriptd_wifi_password(ssid, &password);
            return Some(password);
        }
    }

    None
}

fn password_from_system_airport_keychain(ssid: &str) -> anyhow::Result<Option<String>> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-w",
            "-a",
            ssid,
            "/Library/Keychains/System.keychain",
        ])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((!password.is_empty()).then_some(password))
}

fn import_system_airport_password(ssid: &str) -> Option<String> {
    let password = password_from_system_airport_keychain(ssid).ok().flatten()?;
    if store_scriptd_wifi_password(ssid, &password).is_err() {
        return None;
    }
    Some(password)
}

fn store_scriptd_wifi_password(ssid: &str, password: &str) -> anyhow::Result<()> {
    let service = scriptd_mwifi_keychain_service(ssid);
    credentials::store_generic_password(&service, ssid, password)
}

fn env_key_suffix(ssid: &str) -> String {
    ssid.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn join_output_indicates_failure(output: &str) -> bool {
    let normalized = output.to_ascii_lowercase();
    normalized.contains("failed to join network") || normalized.contains("error:")
}

fn observed_current_ssid(device: &str, networks: &[Network]) -> String {
    let current = current_ssid(device).unwrap_or_default();
    if !current.is_empty() {
        return current;
    }
    current_wifi_signal()
        .ok()
        .flatten()
        .and_then(|signal| infer_current_ssid_from_signal(networks, signal))
        .unwrap_or_default()
}

fn wait_for_connected_ssid(device: &str, target: &str, networks: &[Network]) -> bool {
    for attempt in 0..12 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        if observed_current_ssid(device, networks) == target {
            return true;
        }
    }
    false
}

fn load_config(context: &ModuleContext) -> MwifiConfig {
    let path = context.module_dir.join("module.yaml");
    let mut config =
        match fs::read_to_string(&path).map(|text| serde_yaml::from_str::<MwifiConfig>(&text)) {
            Ok(Ok(value)) => value,
            _ => MwifiConfig::default(),
        };

    let env = EnvMap::default();
    config = resolve_mwifi_config(&config, &env);

    let home_dir = crate::paths::home_dir().to_string_lossy().to_string();
    config.state_file = if config.state_file.is_empty() {
        format!("{home_dir}/.local/share/mwifi/state.txt")
    } else {
        config.state_file
    };
    config.config_path = context
        .module_dir
        .join("module.yaml")
        .to_string_lossy()
        .to_string();
    config
}

fn preferred_ssids(device: &str) -> anyhow::Result<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-listpreferredwirelessnetworks", device])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>())
}

fn setup_candidate_ssids(config: &MwifiConfig, device: &str) -> anyhow::Result<Vec<String>> {
    let preferences = preferred_ssids(device)?;
    let mut ssids = Vec::new();

    for ssid in config.ssids.iter().chain(preferences.iter()) {
        if !ssids.contains(ssid) {
            ssids.push(ssid.clone());
        }
    }

    if ssids.is_empty() {
        let scanned = parse_networks(&[]);
        for network in dedupe_networks(&scanned, config, &[]) {
            if !ssids.contains(&network.ssid) {
                ssids.push(network.ssid);
            }
        }
    }

    Ok(ssids)
}

#[cfg(test)]
fn setup_candidate_ssids_from_lists(configured: &[String], preferences: &[String]) -> Vec<String> {
    let mut ssids = Vec::new();
    for ssid in configured.iter().chain(preferences.iter()) {
        if !ssids.contains(ssid) {
            ssids.push(ssid.clone());
        }
    }
    ssids
}

fn parse_networks(allowed: &[String]) -> Vec<Network> {
    scan_networks(allowed)
}

fn build_candidate(
    network: &Network,
    config: &MwifiConfig,
    priority_order: &[String],
    current_ssid: &str,
    current_health_penalty: f64,
) -> CandidateScore {
    build_candidate_score(
        network,
        config,
        priority_order,
        current_ssid,
        current_health_penalty,
    )
}

fn with_join_failure_penalty(
    mut candidate: CandidateScore,
    join_failure_penalty: f64,
) -> CandidateScore {
    if join_failure_penalty <= 0.0 {
        return candidate;
    }
    candidate.join_failure_penalty = join_failure_penalty;
    candidate.total_score -= join_failure_penalty;
    candidate
}

pub fn run_once(context: &mut ModuleContext) -> anyhow::Result<Option<ModuleStatus>> {
    let config = load_config(context);
    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
    let device = parse_wifi_device()?;
    let now = Utc::now();
    let current = current_ssid(&device)?;
    let preferences = preferred_ssids(&device)?;
    let allowed = if config.ssids.is_empty() {
        preferences
    } else {
        config.ssids.clone()
    };
    let scanned = parse_networks(&allowed);
    let persisted = read_state(&config.state_file);
    let networks = dedupe_networks(&scanned, &config, &allowed);
    let current = if current.is_empty() {
        current_wifi_signal()?
            .and_then(|signal| infer_current_ssid_from_signal(&networks, signal))
            .unwrap_or_default()
    } else {
        current
    };
    let effective = effective_current_ssid(&current, &persisted.last_ssid, &networks);
    let mut join_failures = prune_join_failures(&persisted.join_failures, now);
    if !effective.is_empty() {
        join_failures.remove(&effective);
    }
    let current_health = ping_health(
        &config.ping_target,
        &config,
        persisted.health_failure_streak,
    );
    let next_failure_streak = if current_health.healthy {
        0
    } else {
        persisted.health_failure_streak.saturating_add(1)
    };
    let dwell_satisfied = match &persisted.last_switch_at {
        Some(last) => {
            let last = chrono::DateTime::parse_from_rfc3339(last)
                .map(|value| value.timestamp())
                .unwrap_or(0);
            (now.timestamp() - last) >= config.min_dwell_seconds as i64
        }
        None => true,
    };
    let candidates = networks
        .iter()
        .map(|network| {
            with_join_failure_penalty(
                build_candidate(
                    network,
                    &config,
                    &allowed,
                    &effective,
                    current_health.penalty,
                ),
                if network.ssid == effective {
                    0.0
                } else {
                    join_failure_penalty(&network.ssid, &join_failures, now)
                },
            )
        })
        .collect::<Vec<_>>();
    let decision = decide_wifi_switch(
        &effective,
        &candidates,
        &config,
        dwell_satisfied,
        next_failure_streak,
    );
    state.loop_count = state.loop_count.saturating_add(1);
    state.current_ssid = effective.clone();
    state.last_run_at = Some(now.to_rfc3339());

    let current_description = if !current.is_empty() {
        current.clone()
    } else if !effective.is_empty() {
        format!("unknown; using last known {effective}")
    } else {
        "unknown".to_string()
    };
    let reason = format!(
        "current={}; health=loss:{}% latency:{}ms streak:{}; candidates={}",
        current_description,
        current_health.packet_loss_percent,
        current_health
            .avg_latency_ms
            .map(format_metric)
            .unwrap_or_else(|| "n/a".to_string()),
        next_failure_streak,
        describe_candidates(&candidates),
    );
    context.logger.info(&reason);
    let decision_reason = build_decision_reason(
        &decision,
        &effective,
        &candidates,
        &config,
        next_failure_streak,
    );
    state.last_decision = Some(decision_reason.clone());

    match decision.split(':').next() {
        Some("switch") => {
            let parts = decision.split(':').collect::<Vec<_>>();
            if parts.len() >= 3 {
                let to = parts[2];
                if to == effective {
                    let message =
                        format!("staying on {effective}; chosen SSID already matches current");
                    state.last_decision = Some(message.clone());
                    context.logger.info(&message);
                    return Ok(Some(ModuleStatus {
                        state: "running".to_string(),
                        message: state.last_decision.clone(),
                        started_at: None,
                        last_run_at: state.last_run_at.clone(),
                        next_run_at: None,
                        metrics: Some(HashMap::from([
                            (
                                "loops".to_string(),
                                serde_json::Value::from(state.loop_count),
                            ),
                            (
                                "connected".to_string(),
                                serde_json::Value::String(state.current_ssid.clone()),
                            ),
                        ])),
                    }));
                }
                if let Err(error) = connect_network(&device, to) {
                    let failed_at = Utc::now().to_rfc3339();
                    let message = error.to_string();
                    let mut updated_join_failures = join_failures.clone();
                    updated_join_failures.insert(
                        to.to_string(),
                        StoredJoinFailure {
                            failed_at,
                            message: message.clone(),
                        },
                    );
                    let detected_current = !effective.is_empty();
                    let last_ssid = if detected_current {
                        effective.clone()
                    } else {
                        persisted.last_ssid.clone()
                    };
                    let last_connected_at = if detected_current && persisted.last_ssid != effective
                    {
                        Some(Utc::now().to_rfc3339())
                    } else {
                        persisted.last_connected_at
                    };
                    write_state(
                        &config.state_file,
                        &PersistedWifiState {
                            last_ssid,
                            last_connected_at,
                            last_switch_at: persisted.last_switch_at,
                            health_failure_streak: next_failure_streak,
                            last_health: Some(StoredHealth {
                                packet_loss_percent: current_health.packet_loss_percent,
                                avg_latency_ms: current_health.avg_latency_ms,
                            }),
                            join_failures: updated_join_failures,
                        },
                    );
                    let warning = format!(
                        "{message}; suppressing {to} for {} minutes",
                        JOIN_FAILURE_COOLDOWN_SECONDS / 60
                    );
                    state.last_decision = Some(warning.clone());
                    state.last_error = None;
                    context.logger.warn(&warning);
                    return Ok(Some(ModuleStatus {
                        state: "running".to_string(),
                        message: state.last_decision.clone(),
                        started_at: None,
                        last_run_at: state.last_run_at.clone(),
                        next_run_at: None,
                        metrics: Some(HashMap::from([
                            (
                                "loops".to_string(),
                                serde_json::Value::from(state.loop_count),
                            ),
                            (
                                "connected".to_string(),
                                serde_json::Value::String(state.current_ssid.clone()),
                            ),
                        ])),
                    }));
                }
                if !wait_for_connected_ssid(&device, to, &networks) {
                    let password_retry = run_password_networksetup_join(&device, to);
                    if matches!(password_retry, Some(Ok(())))
                        && wait_for_connected_ssid(&device, to, &networks)
                    {
                        let switched_at = Utc::now().to_rfc3339();
                        let mut updated_join_failures = join_failures.clone();
                        updated_join_failures.remove(to);
                        write_state(
                            &config.state_file,
                            &PersistedWifiState {
                                last_ssid: to.to_string(),
                                last_connected_at: Some(switched_at.clone()),
                                last_switch_at: Some(switched_at.clone()),
                                health_failure_streak: 0,
                                last_health: Some(StoredHealth {
                                    packet_loss_percent: current_health.packet_loss_percent,
                                    avg_latency_ms: current_health.avg_latency_ms,
                                }),
                                join_failures: updated_join_failures,
                            },
                        );
                        state.last_error = None;
                        state.current_ssid = to.to_string();
                        state.last_switch_at = Some(switched_at);
                        context.logger.info(&format!(
                            "{decision_reason}; verified after password-backed networksetup retry"
                        ));
                        return Ok(Some(ModuleStatus {
                            state: "running".to_string(),
                            message: state.last_decision.clone(),
                            started_at: None,
                            last_run_at: state.last_run_at.clone(),
                            next_run_at: None,
                            metrics: Some(HashMap::from([
                                (
                                    "loops".to_string(),
                                    serde_json::Value::from(state.loop_count),
                                ),
                                (
                                    "connected".to_string(),
                                    serde_json::Value::String(state.current_ssid.clone()),
                                ),
                            ])),
                        }));
                    }
                    let elevated = run_sudo_networksetup_join(&device, to)
                        .map_err(|error| error.to_string())
                        .and_then(|attempt| match attempt {
                            JoinAttempt::Succeeded => Ok(()),
                            JoinAttempt::Failed(message) => Err(message),
                        });
                    if elevated.is_ok() && wait_for_connected_ssid(&device, to, &networks) {
                        let switched_at = Utc::now().to_rfc3339();
                        let mut updated_join_failures = join_failures.clone();
                        updated_join_failures.remove(to);
                        write_state(
                            &config.state_file,
                            &PersistedWifiState {
                                last_ssid: to.to_string(),
                                last_connected_at: Some(switched_at.clone()),
                                last_switch_at: Some(switched_at.clone()),
                                health_failure_streak: 0,
                                last_health: Some(StoredHealth {
                                    packet_loss_percent: current_health.packet_loss_percent,
                                    avg_latency_ms: current_health.avg_latency_ms,
                                }),
                                join_failures: updated_join_failures,
                            },
                        );
                        state.last_error = None;
                        state.current_ssid = to.to_string();
                        state.last_switch_at = Some(switched_at);
                        context.logger.info(&format!(
                            "{decision_reason}; verified after elevated networksetup retry"
                        ));
                        return Ok(Some(ModuleStatus {
                            state: "running".to_string(),
                            message: state.last_decision.clone(),
                            started_at: None,
                            last_run_at: state.last_run_at.clone(),
                            next_run_at: None,
                            metrics: Some(HashMap::from([
                                (
                                    "loops".to_string(),
                                    serde_json::Value::from(state.loop_count),
                                ),
                                (
                                    "connected".to_string(),
                                    serde_json::Value::String(state.current_ssid.clone()),
                                ),
                            ])),
                        }));
                    }
                    let failed_at = Utc::now().to_rfc3339();
                    let password_retry_message = match password_retry {
                        Some(Ok(())) => {
                            "password-backed networksetup completed but target was not observed"
                                .to_string()
                        }
                        Some(Err(error)) => {
                            format!("password-backed retry failed: {error}")
                        }
                        None => "no provisioned Wi-Fi password available".to_string(),
                    };
                    let elevated_message = match elevated {
                        Ok(()) => "elevated networksetup completed but target was not observed"
                            .to_string(),
                        Err(error) => format!("elevated retry failed: {error}"),
                    };
                    let message = format!(
                        "networksetup completed but {to} was not observed as current; {password_retry_message}; {elevated_message}"
                    );
                    let mut updated_join_failures = join_failures.clone();
                    updated_join_failures.insert(
                        to.to_string(),
                        StoredJoinFailure {
                            failed_at,
                            message: message.clone(),
                        },
                    );
                    let detected_current = !effective.is_empty();
                    let last_ssid = if detected_current {
                        effective.clone()
                    } else {
                        persisted.last_ssid.clone()
                    };
                    let last_connected_at = if detected_current && persisted.last_ssid != effective
                    {
                        Some(Utc::now().to_rfc3339())
                    } else {
                        persisted.last_connected_at
                    };
                    write_state(
                        &config.state_file,
                        &PersistedWifiState {
                            last_ssid,
                            last_connected_at,
                            last_switch_at: persisted.last_switch_at,
                            health_failure_streak: next_failure_streak,
                            last_health: Some(StoredHealth {
                                packet_loss_percent: current_health.packet_loss_percent,
                                avg_latency_ms: current_health.avg_latency_ms,
                            }),
                            join_failures: updated_join_failures,
                        },
                    );
                    let warning = format!(
                        "{message}; suppressing {to} for {} minutes",
                        JOIN_FAILURE_COOLDOWN_SECONDS / 60
                    );
                    state.last_decision = Some(warning.clone());
                    state.last_error = None;
                    context.logger.warn(&warning);
                    return Ok(Some(ModuleStatus {
                        state: "running".to_string(),
                        message: state.last_decision.clone(),
                        started_at: None,
                        last_run_at: state.last_run_at.clone(),
                        next_run_at: None,
                        metrics: Some(HashMap::from([
                            (
                                "loops".to_string(),
                                serde_json::Value::from(state.loop_count),
                            ),
                            (
                                "connected".to_string(),
                                serde_json::Value::String(state.current_ssid.clone()),
                            ),
                        ])),
                    }));
                }
                let switched_at = Utc::now().to_rfc3339();
                let mut updated_join_failures = join_failures.clone();
                updated_join_failures.remove(to);
                write_state(
                    &config.state_file,
                    &PersistedWifiState {
                        last_ssid: to.to_string(),
                        last_connected_at: Some(switched_at.clone()),
                        last_switch_at: Some(switched_at.clone()),
                        health_failure_streak: 0,
                        last_health: Some(StoredHealth {
                            packet_loss_percent: current_health.packet_loss_percent,
                            avg_latency_ms: current_health.avg_latency_ms,
                        }),
                        join_failures: updated_join_failures,
                    },
                );
                state.last_error = None;
                state.current_ssid = to.to_string();
                state.last_switch_at = Some(switched_at);
                context.logger.info(&decision_reason);
            }
        }
        _ => {
            if networks.is_empty() {
                context.logger.warn(&decision_reason);
            } else {
                context.logger.info(&decision_reason);
            }
            let detected_current = !effective.is_empty();
            let persisted_matches_current = detected_current && persisted.last_ssid == effective;
            let last_ssid = if detected_current {
                effective.clone()
            } else {
                persisted.last_ssid.clone()
            };
            let last_connected_at = if persisted_matches_current {
                persisted.last_connected_at
            } else {
                Some(Utc::now().to_rfc3339())
            };
            let last_switch_at = if detected_current && !persisted_matches_current {
                None
            } else {
                persisted.last_switch_at
            };
            let mut updated_join_failures = join_failures.clone();
            if detected_current {
                updated_join_failures.remove(&effective);
            }
            write_state(
                &config.state_file,
                &PersistedWifiState {
                    last_ssid,
                    last_connected_at,
                    last_switch_at,
                    health_failure_streak: next_failure_streak,
                    last_health: Some(StoredHealth {
                        packet_loss_percent: current_health.packet_loss_percent,
                        avg_latency_ms: current_health.avg_latency_ms,
                    }),
                    join_failures: updated_join_failures,
                },
            );
            state.last_error = None;
        }
    }

    Ok(Some(ModuleStatus {
        state: "running".to_string(),
        message: state.last_decision.clone(),
        started_at: None,
        last_run_at: state.last_run_at.clone(),
        next_run_at: None,
        metrics: Some(HashMap::from([
            (
                "loops".to_string(),
                serde_json::Value::from(state.loop_count),
            ),
            (
                "connected".to_string(),
                serde_json::Value::String(state.current_ssid.clone()),
            ),
        ])),
    }))
}

pub fn setup(context: &mut ModuleContext) -> anyhow::Result<()> {
    let path = context.module_dir.join("module.yaml");
    if !path.exists() {
        return Err(anyhow::anyhow!("Missing module yaml: {}", path.display()));
    }

    let config = load_config(context);
    let device = parse_wifi_device()?;
    let ssids = setup_candidate_ssids(&config, &device)?;

    if ssids.is_empty() {
        context
            .logger
            .warn("No configured or visible preferred Wi-Fi SSIDs found; no passwords imported");
        return Ok(());
    }

    let mut imported = 0usize;
    let mut existing = 0usize;
    let mut skipped = 0usize;

    for ssid in ssids {
        if password_from_scriptd_keychain(&ssid).is_some() {
            existing += 1;
            context.logger.info(&format!(
                "Wi-Fi password for {ssid} is already provisioned in scriptd keychain"
            ));
            continue;
        }

        match password_from_system_airport_keychain(&ssid)? {
            Some(password) => {
                store_scriptd_wifi_password(&ssid, &password)?;
                imported += 1;
                context.logger.info(&format!(
                    "Imported Wi-Fi password for {ssid} into scriptd keychain"
                ));
            }
            None => {
                skipped += 1;
                context.logger.warn(&format!(
                    "No readable System keychain Wi-Fi password found for {ssid}; skipped"
                ));
            }
        }
    }

    if imported == 0 && existing == 0 {
        anyhow::bail!("No Wi-Fi passwords were provisioned for mwifi");
    }

    context.logger.info(&format!(
        "mwifi setup complete; imported {imported}, already provisioned {existing}, skipped {skipped}"
    ));
    Ok(())
}

pub fn status() -> Option<(ModuleStatus, ModuleHealth)> {
    let state = STATE.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(message) = &state.last_error {
        return Some((
            ModuleStatus {
                state: "error".to_string(),
                message: Some(message.clone()),
                started_at: None,
                last_run_at: state.last_run_at.clone(),
                next_run_at: None,
                metrics: Some(HashMap::from([
                    (
                        "loops".to_string(),
                        serde_json::Value::from(state.loop_count),
                    ),
                    (
                        "connected".to_string(),
                        serde_json::Value::String(state.current_ssid.clone()),
                    ),
                ])),
            },
            ModuleHealth {
                ok: false,
                message: Some(message.clone()),
            },
        ));
    }

    Some((
        ModuleStatus {
            state: "running".to_string(),
            message: state.last_decision.clone(),
            started_at: None,
            last_run_at: state.last_run_at.clone(),
            next_run_at: None,
            metrics: Some(HashMap::from([
                (
                    "loops".to_string(),
                    serde_json::Value::from(state.loop_count),
                ),
                (
                    "connected".to_string(),
                    serde_json::Value::String(state.current_ssid.clone()),
                ),
            ])),
        },
        ModuleHealth {
            ok: true,
            message: Some("better wifi healthy".to_string()),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_scoring_prefers_preference_order() {
        let config = MwifiConfig {
            ssids: vec!["Office".to_string(), "Home".to_string()],
            ..Default::default()
        };
        let a = Network {
            ssid: "Office".to_string(),
            band: "5g".to_string(),
            rssi: -40,
            channel: "36".to_string(),
            security: "WPA2".to_string(),
            ping_ms: None,
        };
        let b = Network {
            ssid: "Home".to_string(),
            band: "2g".to_string(),
            rssi: -20,
            channel: "11".to_string(),
            security: "WPA2".to_string(),
            ping_ms: None,
        };
        let score_a = score_network(&a, &config);
        let score_b = score_network(&b, &config);
        assert!(score_a > 0.0);
        assert!(score_b > 0.0);
        assert!(score_a != score_b || a.ssid != b.ssid);
    }

    #[test]
    fn decision_switches_when_gap_big_enough() {
        let config = MwifiConfig {
            min_switch_score_delta: 10.0,
            ..Default::default()
        };
        let current = Network {
            ssid: "Home".to_string(),
            band: "2g".to_string(),
            rssi: -90,
            channel: "1".to_string(),
            security: "WPA2".to_string(),
            ping_ms: None,
        };
        let candidate = Network {
            ssid: "Office".to_string(),
            band: "6g".to_string(),
            rssi: -20,
            channel: "233".to_string(),
            security: "WPA3".to_string(),
            ping_ms: None,
        };
        let candidates = vec![
            build_candidate_score(
                &current,
                &config,
                &["Home".to_string(), "Office".to_string()],
                "Home",
                0.0,
            ),
            build_candidate_score(
                &candidate,
                &config,
                &["Home".to_string(), "Office".to_string()],
                "Home",
                0.0,
            ),
        ];
        let decision = decide_wifi_switch("Home", &candidates, &config, true, 0);
        assert!(decision.contains("switch"));
    }

    #[test]
    fn parse_airport_output_dedupes_and_classifies_bands() {
        let sample =
            "BSSID                  RSSI CHANNEL HT CC SECURITY (auth/unicast/group) HT PHY\n\
TestNet              00:11:22:33:44:55 -55 36 WPA2(PSK/AES/AES)\n\
OldNet               00:AA:22:33:44:55 -40 6 auth\n\
TestNet              00:99:88:77:66:55 -65 233 WPA3(PSK/AES/AES)\n";

        let parsed = parse_airport_output(sample, &["TestNet".to_string(), "OldNet".to_string()]);
        assert_eq!(parsed.len(), 3);
        assert!(parsed.iter().any(|network| network.ssid == "TestNet"));
        let testnet = parsed
            .iter()
            .find(|network| network.ssid == "TestNet")
            .expect("testnet exists");
        assert_eq!(testnet.band, "5g");

        let deduped = dedupe_networks(
            &parsed,
            &default_wifi_config(),
            &["TestNet".to_string(), "OldNet".to_string()],
        );
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn parse_ping_health_scales_penalties() {
        let healthy = parse_ping_health_output(
            "3 packets transmitted, 3 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 10.000/20.000/30.000/1.000 ms",
            250,
            0,
        );
        assert!(healthy.healthy);
        assert_eq!(healthy.penalty, 0.0);

        let degraded = parse_ping_health_output(
            "3 packets transmitted, 2 packets received, 33.3% packet loss\nround-trip min/avg/max/stddev = 10.000/260.000/400.000/1.000 ms",
            250,
            0,
        );
        assert!(!degraded.healthy);
        assert!(degraded.penalty >= 15.0);

        let severe = parse_ping_health_output(
            "3 packets transmitted, 0 packets received, 100.0% packet loss",
            250,
            1,
        );
        assert!(!severe.healthy);
        assert!(severe.severe);

        let severe_zero = parse_ping_health_output(
            "3 packets transmitted, 0 packets received, 100.0% packet loss",
            250,
            0,
        );
        assert!(severe_zero.severe);
        assert_eq!(severe_zero.penalty, 45.0);
        let severe_streak = parse_ping_health_output(
            "3 packets transmitted, 0 packets received, 100.0% packet loss",
            250,
            1,
        );
        assert!(severe_streak.penalty >= 70.0);

        let degraded = ping_health(
            "",
            &MwifiConfig {
                ping_high_latency_ms: 250,
                ..Default::default()
            },
            0,
        );
        assert!(!degraded.healthy);
        assert_eq!(degraded.penalty, 45.0);
    }

    fn default_wifi_config() -> MwifiConfig {
        MwifiConfig {
            min_dwell_seconds: 180,
            ping_target: "1.1.1.1".to_string(),
            ping_count: 3,
            ping_timeout_seconds: 1,
            ping_high_latency_ms: 250,
            health_failure_switch_runs: 2,
            band_bonus_2g: 0.0,
            band_bonus_5g: 35.0,
            band_bonus_6g: 50.0,
            preference_top_bonus: 30.0,
            preference_rank_decay: 5.0,
            current_sticky_bonus: 25.0,
            rssi_offset: 100.0,
            min_switch_score_delta: 10.0,
            ssids: Vec::new(),
            state_file: String::new(),
            config_path: String::new(),
        }
    }

    #[test]
    fn wifi_parses_current_ssid_from_networksetup() {
        assert_eq!(
            parse_networksetup_current_ssid("Current Wi-Fi Network: Yousuf WiFi\n"),
            Some("Yousuf WiFi".to_string())
        );
        assert_eq!(
            parse_networksetup_current_ssid("Current AirPort Network: Office 5G\n"),
            Some("Office 5G".to_string())
        );
        assert_eq!(
            parse_networksetup_current_ssid("You are not associated with an AirPort network.\n"),
            None
        );
        assert_eq!(
            parse_networksetup_current_ssid("Current Wi-Fi Network: <redacted>\n"),
            None
        );
    }

    #[test]
    fn wifi_parses_current_ssid_from_ipconfig_summary() {
        let summary = r#"<dictionary> {
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  NetworkID : 0x123
  SSID : Yousuf WiFi
  Security : WPA2_PSK
}"#;

        assert_eq!(
            parse_ipconfig_current_ssid(summary),
            Some("Yousuf WiFi".to_string())
        );
        assert_eq!(parse_ipconfig_current_ssid("  SSID : <redacted>\n"), None);
    }

    #[test]
    fn wifi_infers_current_ssid_from_unique_signal_match() {
        let networks = vec![
            Network {
                ssid: "Yousuf WiFi".to_string(),
                band: "2g".to_string(),
                rssi: -61,
                channel: "10".to_string(),
                security: "WPA2".to_string(),
                ping_ms: None,
            },
            Network {
                ssid: "knight_riders_5G".to_string(),
                band: "5g".to_string(),
                rssi: -65,
                channel: "161".to_string(),
                security: "WPA2".to_string(),
                ping_ms: None,
            },
        ];

        assert_eq!(
            parse_wifi_signal_output("10\t-67\n"),
            Some(WifiSignal {
                channel: 10,
                rssi: -67,
            })
        );
        assert_eq!(
            infer_current_ssid_from_signal(
                &networks,
                WifiSignal {
                    channel: 10,
                    rssi: -67,
                }
            ),
            Some("Yousuf WiFi".to_string())
        );
    }

    #[test]
    fn wifi_does_not_infer_current_ssid_from_ambiguous_signal_match() {
        let networks = vec![
            Network {
                ssid: "first".to_string(),
                band: "2g".to_string(),
                rssi: -61,
                channel: "10".to_string(),
                security: "WPA2".to_string(),
                ping_ms: None,
            },
            Network {
                ssid: "second".to_string(),
                band: "2g".to_string(),
                rssi: -61,
                channel: "10".to_string(),
                security: "WPA2".to_string(),
                ping_ms: None,
            },
        ];

        assert_eq!(
            infer_current_ssid_from_signal(
                &networks,
                WifiSignal {
                    channel: 10,
                    rssi: -64,
                }
            ),
            None
        );
    }

    #[test]
    fn wifi_join_output_detects_networksetup_failure_with_zero_exit_style_output() {
        assert!(join_output_indicates_failure(
            "Failed to join network knight_riders_5G.\nError: -3900  The operation couldn't be completed."
        ));
        assert!(!join_output_indicates_failure(""));
    }

    #[test]
    fn wifi_join_failure_penalty_expires_after_cooldown() {
        let now = Utc::now();
        let mut failures = HashMap::new();
        failures.insert(
            "blocked".to_string(),
            StoredJoinFailure {
                failed_at: now.to_rfc3339(),
                message: "failed".to_string(),
            },
        );
        failures.insert(
            "old".to_string(),
            StoredJoinFailure {
                failed_at: (now - chrono::Duration::minutes(20)).to_rfc3339(),
                message: "old failure".to_string(),
            },
        );

        let pruned = prune_join_failures(&failures, now);
        assert!(pruned.contains_key("blocked"));
        assert!(!pruned.contains_key("old"));
        assert_eq!(
            join_failure_penalty("blocked", &pruned, now),
            JOIN_FAILURE_SCORE_PENALTY
        );
        assert_eq!(join_failure_penalty("old", &pruned, now), 0.0);
    }

    #[test]
    fn wifi_password_env_key_suffix_is_shell_safe() {
        assert_eq!(env_key_suffix("knight_riders_5G"), "KNIGHT_RIDERS_5G");
        assert_eq!(env_key_suffix("Yousuf WiFi"), "YOUSUF_WIFI");
        assert_eq!(
            scriptd_mwifi_keychain_service("knight_riders_5G"),
            "scriptd-mwifi:knight_riders_5G"
        );
    }

    #[test]
    fn wifi_setup_imports_configured_and_all_preferred_ssids() {
        let configured = vec!["knight_riders_5G".to_string(), "Yousuf WiFi".to_string()];
        let preferences = vec![
            "Yousuf WiFi".to_string(),
            "Cafe".to_string(),
            "knight_riders".to_string(),
        ];

        assert_eq!(
            setup_candidate_ssids_from_lists(&configured, &preferences),
            vec![
                "knight_riders_5G".to_string(),
                "Yousuf WiFi".to_string(),
                "Cafe".to_string(),
                "knight_riders".to_string(),
            ]
        );
    }

    #[test]
    fn wifi_decision_prefers_current_network_when_below_threshold() {
        let config = MwifiConfig {
            min_switch_score_delta: 25.0,
            ..Default::default()
        };
        let candidates = vec![
            build_candidate_score(
                &Network {
                    ssid: "Home".to_string(),
                    band: "5g".to_string(),
                    rssi: -50,
                    channel: "36".to_string(),
                    security: "WPA2".to_string(),
                    ping_ms: None,
                },
                &config,
                &["Home".to_string(), "Office".to_string()],
                "Home",
                0.0,
            ),
            build_candidate_score(
                &Network {
                    ssid: "Office".to_string(),
                    band: "6g".to_string(),
                    rssi: -48,
                    channel: "233".to_string(),
                    security: "WPA3".to_string(),
                    ping_ms: None,
                },
                &config,
                &["Home".to_string(), "Office".to_string()],
                "Home",
                0.0,
            ),
        ];

        let decision = decide_wifi_switch("Home", &candidates, &config, true, 0);
        assert_eq!(decision, "stay:Home");
    }

    #[test]
    fn wifi_decision_switches_when_non_sticky_score_clears_threshold() {
        let config = MwifiConfig {
            min_switch_score_delta: 25.0,
            current_sticky_bonus: 25.0,
            ..Default::default()
        };
        let candidates = vec![
            build_candidate_score(
                &Network {
                    ssid: "Yousuf WiFi".to_string(),
                    band: "2g".to_string(),
                    rssi: -67,
                    channel: "10".to_string(),
                    security: "WPA2".to_string(),
                    ping_ms: None,
                },
                &config,
                &["Yousuf WiFi".to_string(), "knight_riders_5G".to_string()],
                "Yousuf WiFi",
                0.0,
            ),
            build_candidate_score(
                &Network {
                    ssid: "knight_riders_5G".to_string(),
                    band: "5g".to_string(),
                    rssi: -70,
                    channel: "161".to_string(),
                    security: "WPA2".to_string(),
                    ping_ms: None,
                },
                &config,
                &["Yousuf WiFi".to_string(), "knight_riders_5G".to_string()],
                "Yousuf WiFi",
                0.0,
            ),
        ];

        assert_eq!(
            switch_score(&candidates[1]) - switch_score(&candidates[0]),
            27.0
        );
        assert_eq!(
            decide_wifi_switch("Yousuf WiFi", &candidates, &config, true, 0),
            "switch:Yousuf WiFi:knight_riders_5G"
        );
    }

    #[test]
    fn wifi_decision_switches_after_health_failure_streak() {
        let config = MwifiConfig {
            min_switch_score_delta: 1_000.0,
            health_failure_switch_runs: 2,
            ..Default::default()
        };

        let candidates = vec![
            build_candidate_score(
                &Network {
                    ssid: "Home".to_string(),
                    band: "5g".to_string(),
                    rssi: -90,
                    channel: "36".to_string(),
                    security: "WPA2".to_string(),
                    ping_ms: None,
                },
                &config,
                &["Home".to_string(), "Office".to_string()],
                "Home",
                70.0,
            ),
            build_candidate_score(
                &Network {
                    ssid: "Office".to_string(),
                    band: "6g".to_string(),
                    rssi: -20,
                    channel: "11".to_string(),
                    security: "WPA2".to_string(),
                    ping_ms: None,
                },
                &config,
                &["Home".to_string(), "Office".to_string()],
                "Home",
                70.0,
            ),
        ];

        let stay = decide_wifi_switch("Home", &candidates, &config, true, 1);
        let switch = decide_wifi_switch("Home", &candidates, &config, true, 2);
        assert_eq!(stay, "stay:Home");
        assert_eq!(switch, "switch:Home:Office");
    }

    #[test]
    fn wifi_effective_current_ssid_does_not_use_last_known_when_undetected() {
        let known = vec![
            Network {
                ssid: "stored".to_string(),
                band: "5g".to_string(),
                rssi: -55,
                channel: "149".to_string(),
                security: "WPA2".to_string(),
                ping_ms: None,
            },
            Network {
                ssid: "other".to_string(),
                band: "2g".to_string(),
                rssi: -60,
                channel: "6".to_string(),
                security: "WPA2".to_string(),
                ping_ms: None,
            },
        ];

        assert_eq!(effective_current_ssid("", "stored", &known), "");
        assert_eq!(effective_current_ssid("", "missing", &known), "");
        assert_eq!(
            effective_current_ssid("visible", "stored", &known),
            "visible"
        );
    }

    #[test]
    fn wifi_resolves_env_overrides() {
        let mut raw = default_wifi_config();
        raw.ping_target = "192.0.2.1".to_string();

        let env = EnvMap {
            values: vec![
                ("MWIFI_SSIDS".to_string(), "Office,Lab".to_string()),
                ("MWIFI_PING_TARGET".to_string(), "8.8.8.8".to_string()),
                (
                    "MWIFI_MIN_SWITCH_SCORE_DELTA".to_string(),
                    "41.5".to_string(),
                ),
                ("MWIFI_PING_COUNT".to_string(), "7".to_string()),
            ]
            .into_iter()
            .collect(),
        };

        let resolved = resolve_mwifi_config(&raw, &env);
        assert_eq!(resolved.ping_target, "8.8.8.8");
        assert_eq!(resolved.min_switch_score_delta, 41.5);
        assert_eq!(resolved.ping_count, 7);
        assert_eq!(
            resolved.ssids,
            vec!["Office".to_string(), "Lab".to_string()]
        );
    }

    #[test]
    fn wifi_resolves_module_yaml_state_file_when_env_absent() {
        let mut raw = default_wifi_config();
        raw.state_file = "/tmp/scriptd-mwifi-state.json".to_string();

        let resolved = resolve_mwifi_config(
            &raw,
            &EnvMap {
                values: std::collections::HashMap::new(),
            },
        );

        assert_eq!(resolved.state_file, "/tmp/scriptd-mwifi-state.json");
    }

    #[test]
    fn wifi_band_bonus_favors_6g_over_5g() {
        let config = default_wifi_config();
        let network_5g = Network {
            ssid: "Office5g".to_string(),
            band: "5g".to_string(),
            rssi: -60,
            channel: "44".to_string(),
            security: "WPA2".to_string(),
            ping_ms: None,
        };
        let network_6g = Network {
            ssid: "Office6g".to_string(),
            band: "6g".to_string(),
            rssi: -60,
            channel: "233".to_string(),
            security: "WPA3".to_string(),
            ping_ms: None,
        };

        let score_5g = score_network(&network_5g, &config);
        let score_6g = score_network(&network_6g, &config);
        assert!(score_6g > score_5g);
    }
}
