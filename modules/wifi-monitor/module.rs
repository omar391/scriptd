#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use chrono::Utc;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiMonitorConfig {
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

impl Default for WifiMonitorConfig {
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
            min_switch_score_delta: 25.0,
            ssids: Vec::new(),
            state_file: String::new(),
            config_path: String::new(),
        }
    }
}

#[allow(dead_code)]
pub fn resolve_wifi_monitor_config(raw: &WifiMonitorConfig, env: &EnvMap) -> WifiMonitorConfig {
    let env_ssids = env
        .get("WIFI_MONITOR_SSIDS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let state_file = env
        .get("WIFI_MONITOR_STATE_FILE")
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            if raw.state_file.is_empty() {
                let home = crate::paths::home_dir();
                home.join(".local/share/wifi-monitor/state.json")
                    .to_string_lossy()
                    .to_string()
            } else {
                raw.state_file.clone()
            }
        });

    let config_path = env
        .get("WIFI_MONITOR_CONFIG_PATH")
        .map(ToString::to_string)
        .unwrap_or_else(|| raw.config_path.clone());

    WifiMonitorConfig {
        min_dwell_seconds: parse_env_u64(env.get("WIFI_MONITOR_MIN_DWELL"), raw.min_dwell_seconds),
        ping_target: env
            .get("WIFI_MONITOR_PING_TARGET")
            .unwrap_or(raw.ping_target.as_str())
            .to_string(),
        ping_count: parse_env_u64(env.get("WIFI_MONITOR_PING_COUNT"), raw.ping_count),
        ping_timeout_seconds: parse_env_u64(
            env.get("WIFI_MONITOR_PING_TIMEOUT"),
            raw.ping_timeout_seconds,
        ),
        ping_high_latency_ms: parse_env_u64(
            env.get("WIFI_MONITOR_PING_HIGH_LATENCY_MS"),
            raw.ping_high_latency_ms,
        ),
        health_failure_switch_runs: parse_env_u64(
            env.get("WIFI_MONITOR_HEALTH_FAILURE_SWITCH_RUNS"),
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
            env.get("WIFI_MONITOR_MIN_SWITCH_SCORE_DELTA"),
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
}

#[derive(Debug, Clone)]
struct StoredHealth {
    packet_loss_percent: f64,
    avg_latency_ms: Option<f64>,
}

#[derive(Debug, Default)]
struct WifiMonitorState {
    current_ssid: String,
    last_switch_at: Option<String>,
    last_decision: Option<String>,
    last_run_at: Option<String>,
    loop_count: u64,
    last_error: Option<String>,
}

static STATE: once_cell::sync::Lazy<std::sync::Mutex<WifiMonitorState>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(WifiMonitorState::default()));

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
    pub total_score: f64,
}

fn read_state(state_file: &str) -> PersistedWifiState {
    let Ok(raw) = fs::read_to_string(state_file) else {
        return PersistedWifiState {
            last_ssid: String::new(),
            last_connected_at: None,
            last_switch_at: None,
            health_failure_streak: 0,
            last_health: None,
        };
    };

    let json = serde_json::from_str::<serde_json::Value>(&raw).ok();
    if let Some(value) = json {
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
        };
    }

    PersistedWifiState {
        last_ssid: String::new(),
        last_connected_at: None,
        last_switch_at: None,
        health_failure_streak: 0,
        last_health: None,
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
    let _ = fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::Value::Object(data)).unwrap_or_default(),
    );
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
    anyhow::bail!("Could not detect wifi device")
}

fn current_ssid(device: &str) -> anyhow::Result<String> {
    let output = Command::new("networksetup")
        .args(["-getairportnetwork", device])
        .output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let prefix = "Current Wi-Fi Network: ";
    Ok(text
        .lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim).map(str::to_string))
        .unwrap_or_default())
}

fn parse_airport_output(output: &str, allowed: &[String]) -> Vec<Network> {
    let mut out = Vec::new();
    for line in output.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let ssid = parts
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if ssid.is_none() {
            continue;
        }
        let ssid = ssid.unwrap_or_default().to_string();
        if !allowed.is_empty() && !allowed.iter().any(|value| value == &ssid) {
            continue;
        }
        let _bssid = parts.next();
        let rssi = parts
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(-999);
        let channel = parts.next().unwrap_or("1").to_string();
        let security = parts.collect::<Vec<_>>().join(" ");
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
    if let Ok(output) = std::env::var("SCRIPTD_WIFI_SCAN_OUTPUT") {
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
        std::env::var("SCRIPTD_WIFI_SCAN_FALLBACK")
            .ok()
            .map(|_| String::new())
    });
    let output = output.unwrap_or_default();
    if output.is_empty() {
        Vec::new()
    } else {
        parse_airport_output(&output, allowed)
    }
}

fn command_time_ms(output: &str) -> Option<f64> {
    if output.is_empty() {
        return None;
    }
    for token in output.split_whitespace() {
        if token.ends_with("ms") {
            let numeric = token.trim_end_matches("ms").parse::<f64>().ok()?;
            return Some(numeric);
        }
    }
    let has_ms = output.split('\n').find_map(|line| {
        line.split('=')
            .find_map(|value| value.trim().parse::<f64>().ok())
    });
    has_ms
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

pub fn ping_health(target: &str, config: &WifiMonitorConfig, prior_streak: u64) -> PingHealth {
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

fn score_band(network: &Network, config: &WifiMonitorConfig) -> f64 {
    let band_bonus = if network.band == "6g" {
        config.band_bonus_6g
    } else if network.band == "5g" {
        config.band_bonus_5g
    } else {
        config.band_bonus_2g
    };
    let rssi_score = (network.rssi as f64 + config.rssi_offset).clamp(0.0, 100.0);
    band_bonus + rssi_score
}

fn preference_bonus(rank: usize, config: &WifiMonitorConfig) -> f64 {
    if rank == usize::MAX {
        0.0
    } else {
        (config.preference_top_bonus - (rank as f64 * config.preference_rank_decay)).max(0.0)
    }
}

pub fn build_candidate_score(
    network: &Network,
    config: &WifiMonitorConfig,
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

    CandidateScore {
        network: network.clone(),
        rank,
        rssi_score,
        band_bonus,
        preference_bonus: preference,
        sticky_bonus: sticky,
        health_penalty,
        total_score: rssi_score + band_bonus + preference + sticky - health_penalty,
    }
}

fn dedupe_networks(
    networks: &[Network],
    config: &WifiMonitorConfig,
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

fn score_network(network: &Network, config: &WifiMonitorConfig) -> f64 {
    score_band(network, config)
}

pub fn describe_candidates(candidates: &[CandidateScore]) -> String {
    if candidates.is_empty() {
        return "none".to_string();
    }
    let mut lines = candidates
        .iter()
        .map(|candidate| {
            format!(
                "{}(band={},rssi={},pref={},bandBonus={},sticky={},penalty={},total={})",
                candidate.network.ssid,
                candidate.network.band,
                candidate.network.rssi,
                candidate.preference_bonus,
                candidate.band_bonus,
                candidate.sticky_bonus,
                candidate.health_penalty,
                candidate.total_score
            )
        })
        .collect::<Vec<_>>();
    lines.sort_unstable();
    lines.join("; ")
}

pub fn effective_current_ssid(current: &str, persisted: &str, networks: &[Network]) -> String {
    if !current.is_empty() {
        return current.to_string();
    }
    if !persisted.is_empty() && networks.iter().any(|network| network.ssid == persisted) {
        return persisted.to_string();
    }
    String::new()
}

pub fn decide_wifi_switch(
    current: &str,
    candidates: &[CandidateScore],
    config: &WifiMonitorConfig,
    dwell_satisfied: bool,
    health_failure_streak: u64,
) -> String {
    let ranked = {
        let mut ranked = candidates.to_vec();
        ranked.sort_by(|left, right| {
            right
                .total_score
                .total_cmp(&left.total_score)
                .then(right.rank.cmp(&left.rank))
        });
        ranked
    };
    let best = ranked.first();
    if best.is_none() {
        return format!("stay:{current}");
    }
    let best = best.expect("candidate exists");
    let current_candidate = ranked
        .iter()
        .find(|candidate| candidate.network.ssid == current)
        .or(Some(best));
    let current = current_candidate
        .expect("current candidate should exist")
        .clone();
    let delta = best.total_score - current.total_score;
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

fn connect_network(device: &str, ssid: &str) -> anyhow::Result<()> {
    let status = Command::new("networksetup")
        .args(["-setairportnetwork", device, ssid])
        .status()?;
    if !status.success() {
        anyhow::bail!("Could not switch Wi-Fi to {ssid}");
    }
    Ok(())
}

fn load_config(context: &ModuleContext) -> WifiMonitorConfig {
    let path = context.module_dir.join("module.yaml");
    let mut config = match fs::read_to_string(&path)
        .map(|text| serde_yaml::from_str::<WifiMonitorConfig>(&text))
    {
        Ok(Ok(value)) => value,
        _ => WifiMonitorConfig::default(),
    };

    let env = EnvMap::default();
    config = resolve_wifi_monitor_config(&config, &env);

    let home_dir = crate::paths::home_dir().to_string_lossy().to_string();
    config.state_file = if config.state_file.is_empty() {
        format!("{home_dir}/.local/share/wifi-monitor/state.json")
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

fn parse_networks(allowed: &[String]) -> Vec<Network> {
    scan_networks(allowed)
}

fn build_candidate(
    network: &Network,
    config: &WifiMonitorConfig,
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

pub fn run_once(context: &mut ModuleContext) -> anyhow::Result<Option<ModuleStatus>> {
    let config = load_config(context);
    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
    let device = parse_wifi_device()?;
    let now = Utc::now();
    let current = current_ssid(&device)?;
    let preferences = {
        let output = Command::new("networksetup")
            .args(["-listpreferredwirelessnetworks", &device])
            .output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .skip(1)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let allowed = if config.ssids.is_empty() {
        preferences
    } else {
        config.ssids.clone()
    };
    let scanned = parse_networks(&allowed);
    let persisted = read_state(&config.state_file);
    let networks = dedupe_networks(&scanned, &config, &allowed);
    let effective = effective_current_ssid(&current, &persisted.last_ssid, &networks);
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
            build_candidate(
                network,
                &config,
                &allowed,
                &effective,
                current_health.penalty,
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

    let reason = format!(
        "current={}; health=loss:{} latency:{:?} streak:{}; candidates={}",
        effective,
        current_health.packet_loss_percent,
        current_health.avg_latency_ms,
        next_failure_streak,
        describe_candidates(&candidates),
    );
    context.logger.info(&reason);

    match decision.split(':').next() {
        Some("switch") => {
            let parts = decision.split(':').collect::<Vec<_>>();
            if parts.len() >= 3 {
                let to = parts[2];
                connect_network(&device, to)?;
                let switched_at = Utc::now().to_rfc3339();
                write_state(
                    &config.state_file,
                    &PersistedWifiState {
                        last_ssid: to.to_string(),
                        last_connected_at: Some(switched_at.clone()),
                        last_switch_at: Some(switched_at),
                        health_failure_streak: 0,
                        last_health: Some(StoredHealth {
                            packet_loss_percent: current_health.packet_loss_percent,
                            avg_latency_ms: current_health.avg_latency_ms,
                        }),
                    },
                );
                state.last_error = None;
                state.last_decision = Some(format!("switch {current} -> {to}"));
                state.last_switch_at = state.last_decision.clone();
                context
                    .logger
                    .info(state.last_decision.as_deref().unwrap_or("switched wifi"));
            }
        }
        _ => {
            write_state(
                &config.state_file,
                &PersistedWifiState {
                    last_ssid: effective,
                    last_connected_at: persisted
                        .last_connected_at
                        .or(Some(Utc::now().to_rfc3339())),
                    last_switch_at: persisted.last_switch_at,
                    health_failure_streak: next_failure_streak,
                    last_health: Some(StoredHealth {
                        packet_loss_percent: current_health.packet_loss_percent,
                        avg_latency_ms: current_health.avg_latency_ms,
                    }),
                },
            );
            state.last_error = None;
            state.last_decision = Some(format!("stay {}", reason));
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
            message: Some("wifi monitor healthy".to_string()),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_scoring_prefers_preference_order() {
        let config = WifiMonitorConfig {
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
        let config = WifiMonitorConfig {
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
            &WifiMonitorConfig {
                ping_high_latency_ms: 250,
                ..Default::default()
            },
            0,
        );
        assert!(!degraded.healthy);
        assert_eq!(degraded.penalty, 45.0);
    }

    fn default_wifi_config() -> WifiMonitorConfig {
        WifiMonitorConfig {
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
            min_switch_score_delta: 25.0,
            ssids: Vec::new(),
            state_file: String::new(),
            config_path: String::new(),
        }
    }

    #[test]
    fn wifi_decision_prefers_current_network_when_below_threshold() {
        let config = WifiMonitorConfig {
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
    fn wifi_decision_switches_after_health_failure_streak() {
        let config = WifiMonitorConfig {
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
    fn wifi_effective_current_ssid_prefers_last_known_when_undetected() {
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

        assert_eq!(effective_current_ssid("", "stored", &known), "stored");
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
                ("WIFI_MONITOR_SSIDS".to_string(), "Office,Lab".to_string()),
                (
                    "WIFI_MONITOR_PING_TARGET".to_string(),
                    "8.8.8.8".to_string(),
                ),
                (
                    "WIFI_MONITOR_MIN_SWITCH_SCORE_DELTA".to_string(),
                    "41.5".to_string(),
                ),
                ("WIFI_MONITOR_PING_COUNT".to_string(), "7".to_string()),
            ]
            .into_iter()
            .collect(),
        };

        let resolved = resolve_wifi_monitor_config(&raw, &env);
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
        raw.state_file = "/tmp/scriptd-wifi-state.json".to_string();

        let resolved = resolve_wifi_monitor_config(
            &raw,
            &EnvMap {
                values: std::collections::HashMap::new(),
            },
        );

        assert_eq!(resolved.state_file, "/tmp/scriptd-wifi-state.json");
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
