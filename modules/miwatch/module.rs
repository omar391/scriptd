#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;

use crate::modules::{ModuleContext, ModuleHealth, ModuleInvocation, ModuleStatus};
use crate::paths::{expand_home, resolve_state_dir};

const DEFAULT_COOLDOWN_SECONDS: u64 = 30 * 60;
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_ACCESS_TOKEN_FIELD: &str = "access_token";
const DEFAULT_REFRESH_TOKEN_FIELD: &str = "refresh_token";
const DEFAULT_EXPIRES_AT_FIELD: &str = "expires_at";
const XIAOMI_REBOOT_PATH: &str = "/s/diagnosis/control/reboot";
const XIAOMI_INIT_INFO_PATH: &str = "/r/api/xqsystem/init_info";
const DEFAULT_XIAOMI_BASE_URL: &str = "https://api.miwifi.com";
const DEFAULT_XIAOMI_ACCOUNT_BASE_URL: &str = "https://account.xiaomi.com";
const XIAOMI_ACCOUNT_SERVICE_LOGIN_PATH: &str = "/pass/serviceLogin";
const CURL_STATUS_MARKER: &str = "__SCRIPTD_HTTP_STATUS__";
const EMULATOR_COLLECTOR_DEX: &str = "/data/local/tmp/miwatch-collector.dex";

#[derive(Debug, Clone, Deserialize)]
pub struct WatchdogConfig {
    #[serde(rename = "ssid", default)]
    legacy_ssid: Option<String>,
    #[serde(rename = "timezone", default)]
    legacy_timezone: Option<String>,
    #[serde(rename = "window_start", default)]
    legacy_window_start: Option<String>,
    #[serde(rename = "window_end", default)]
    legacy_window_end: Option<String>,
    #[serde(rename = "failure_threshold", default)]
    legacy_failure_threshold: Option<u32>,
    #[serde(default = "default_cooldown_seconds")]
    pub cooldown_seconds: u64,
    #[serde(default)]
    pub state_file: String,
    #[serde(default)]
    pub token_file: String,
    #[serde(default)]
    pub verified_remote_api: bool,
    #[serde(default)]
    pub remote: RemoteApiConfig,
}

fn default_cooldown_seconds() -> u64 {
    DEFAULT_COOLDOWN_SECONDS
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            legacy_ssid: None,
            legacy_timezone: None,
            legacy_window_start: None,
            legacy_window_end: None,
            legacy_failure_threshold: None,
            cooldown_seconds: default_cooldown_seconds(),
            state_file: String::new(),
            token_file: String::new(),
            verified_remote_api: false,
            remote: RemoteApiConfig::default(),
        }
    }
}

impl WatchdogConfig {
    fn validate(&self) -> Result<()> {
        if self.legacy_ssid.is_some()
            || self.legacy_timezone.is_some()
            || self.legacy_window_start.is_some()
            || self.legacy_window_end.is_some()
            || self.legacy_failure_threshold.is_some()
        {
            anyhow::bail!(
                "miwatch SSID, timezone/window, and debounce fields moved to top-level triggers"
            );
        }
        if self.cooldown_seconds == 0 || i64::try_from(self.cooldown_seconds).is_err() {
            anyhow::bail!("miwatch cooldown_seconds must be between 1 and i64::MAX");
        }
        self.remote.validate(self.verified_remote_api)
    }

    fn resolved_state_file(&self) -> PathBuf {
        if self.state_file.is_empty() {
            resolve_state_dir().join("miwatch_state.json")
        } else {
            expand_home(&self.state_file)
        }
    }

    fn resolved_token_file(&self) -> PathBuf {
        if self.token_file.is_empty() {
            resolve_state_dir().join("miwatch_session.json")
        } else {
            expand_home(&self.token_file)
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteApiConfig {
    #[serde(default)]
    pub xiaomi: Option<XiaomiRemoteConfig>,
    #[serde(default)]
    pub reboot: Option<RequestTemplate>,
    #[serde(default)]
    pub refresh: Option<RequestTemplate>,
    #[serde(default = "default_access_token_field")]
    pub access_token_field: String,
    #[serde(default = "default_refresh_token_field")]
    pub refresh_token_field: String,
    #[serde(default = "default_expires_at_field")]
    pub expires_at_field: String,
    #[serde(default = "default_request_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl Default for RemoteApiConfig {
    fn default() -> Self {
        Self {
            xiaomi: None,
            reboot: None,
            refresh: None,
            access_token_field: default_access_token_field(),
            refresh_token_field: default_refresh_token_field(),
            expires_at_field: default_expires_at_field(),
            timeout_seconds: default_request_timeout_seconds(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct XiaomiRemoteConfig {
    #[serde(default = "default_xiaomi_base_url")]
    pub base_url: String,
    #[serde(default = "default_xiaomi_account_base_url")]
    pub account_base_url: String,
    #[serde(default)]
    pub router_private_id: Option<String>,
    pub user_agent: String,
    #[serde(default)]
    pub success_statuses: Vec<u16>,
}

fn default_xiaomi_base_url() -> String {
    DEFAULT_XIAOMI_BASE_URL.to_string()
}

fn default_xiaomi_account_base_url() -> String {
    DEFAULT_XIAOMI_ACCOUNT_BASE_URL.to_string()
}

impl XiaomiRemoteConfig {
    fn validate(&self) -> Result<()> {
        if !matches!(
            self.base_url.as_str(),
            "https://api.miwifi.com" | "https://eu.api.miwifi.com" | "https://in.api.miwifi.com"
        ) {
            anyhow::bail!("Mi WiFi base_url must be an official regional API base");
        }
        if self.account_base_url != DEFAULT_XIAOMI_ACCOUNT_BASE_URL {
            anyhow::bail!("Mi WiFi account_base_url must be https://account.xiaomi.com");
        }
        if self.user_agent.trim().is_empty() {
            anyhow::bail!("Mi WiFi user_agent must not be empty");
        }
        Ok(())
    }

    fn success_statuses(&self) -> &[u16] {
        if self.success_statuses.is_empty() {
            &[200]
        } else {
            &self.success_statuses
        }
    }
}

fn default_access_token_field() -> String {
    DEFAULT_ACCESS_TOKEN_FIELD.to_string()
}

fn default_refresh_token_field() -> String {
    DEFAULT_REFRESH_TOKEN_FIELD.to_string()
}

fn default_expires_at_field() -> String {
    DEFAULT_EXPIRES_AT_FIELD.to_string()
}

fn default_request_timeout_seconds() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECONDS
}

impl RemoteApiConfig {
    fn validate(&self, verified: bool) -> Result<()> {
        if !verified {
            return Ok(());
        }
        if let Some(xiaomi) = &self.xiaomi {
            xiaomi.validate()?;
        }
        let xiaomi = self
            .xiaomi
            .as_ref()
            .context("verified_remote_api requires the exact Xiaomi request profile")?;
        xiaomi.validate()?;
        if let Some(refresh) = &self.refresh {
            refresh.validate()?;
        }
        if self.access_token_field.trim().is_empty()
            || self.refresh_token_field.trim().is_empty()
            || self.expires_at_field.trim().is_empty()
        {
            anyhow::bail!("remote token response fields must not be empty");
        }
        if self.timeout_seconds == 0 {
            anyhow::bail!("remote request timeout_seconds must be greater than zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestTemplate {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub success_statuses: Vec<u16>,
}

impl RequestTemplate {
    fn validate(&self) -> Result<()> {
        if self.method.trim().is_empty() || self.url.trim().is_empty() {
            anyhow::bail!("remote request method and url are required");
        }
        if self.url.contains('\n') || self.url.contains('\r') {
            anyhow::bail!("remote request url contains a newline");
        }
        Ok(())
    }

    fn success_statuses(&self) -> &[u16] {
        if self.success_statuses.is_empty() {
            &[200, 201, 202, 204]
        } else {
            &self.success_statuses
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SessionTokens {
    /// Legacy generic profile field retained for compatibility with local
    /// mock tests. Xiaomi requests use `service_token` and `ssecurity`.
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub service_token: Option<String>,
    #[serde(default)]
    pub ssecurity: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub c_user_id: Option<String>,
    #[serde(default)]
    pub pass_token: Option<String>,
    #[serde(default)]
    pub router_private_id: Option<String>,
    #[serde(default)]
    pub time_diff_ms: i64,
    #[serde(default)]
    pub cookies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct WatchdogState {
    #[serde(default)]
    pub reboot_attempted: bool,
    #[serde(default)]
    pub last_reboot_at: Option<String>,
    #[serde(default)]
    pub cooldown_until: Option<String>,
    #[serde(default)]
    pub last_outcome: Option<String>,
    #[serde(default)]
    pub last_incident_id: Option<String>,
    #[serde(default)]
    pub attempt_started_at: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RemoteCallOutcome {
    Accepted { status: u16 },
    Rejected { status: u16 },
    Ambiguous { reason: String },
}

pub trait RemoteRebooter {
    fn reboot(&mut self) -> Result<RemoteCallOutcome>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TickOutcome {
    Cooldown,
    AlreadyAttempted,
    RebootAccepted { status: u16 },
    RebootRejected { status: u16 },
    RebootAmbiguous,
}

fn execute_incident<R: RemoteRebooter>(
    state: &mut WatchdogState,
    config: &WatchdogConfig,
    incident_id: &str,
    now: DateTime<Utc>,
    state_path: &Path,
    rebooter: &mut R,
) -> Result<TickOutcome> {
    if state.last_incident_id.as_deref() == Some(incident_id) && state.reboot_attempted {
        return Ok(TickOutcome::AlreadyAttempted);
    }
    if parse_utc(state.cooldown_until.as_deref()).is_some_and(|until| until > now) {
        return Ok(TickOutcome::Cooldown);
    }

    state.last_incident_id = Some(incident_id.to_string());
    state.attempt_started_at = Some(now.to_rfc3339());
    state.reboot_attempted = true;
    state.last_reboot_at = Some(now.to_rfc3339());
    state.cooldown_until = now
        .checked_add_signed(Duration::seconds(config.cooldown_seconds as i64))
        .map(|value| value.to_rfc3339());
    state.last_outcome = Some("attempt_started".to_string());
    save_state(state_path, state)?;

    let outcome = match rebooter.reboot()? {
        RemoteCallOutcome::Accepted { status } => {
            state.last_outcome = Some("reboot_accepted".to_string());
            TickOutcome::RebootAccepted { status }
        }
        RemoteCallOutcome::Rejected { status } => {
            state.last_outcome = Some("reboot_rejected".to_string());
            TickOutcome::RebootRejected { status }
        }
        RemoteCallOutcome::Ambiguous { .. } => {
            state.last_outcome = Some("reboot_ambiguous".to_string());
            TickOutcome::RebootAmbiguous
        }
    };
    save_state(state_path, state)?;
    Ok(outcome)
}

fn parse_utc(raw: Option<&str>) -> Option<DateTime<Utc>> {
    raw.and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

#[derive(Debug, Clone)]
struct PreparedRequest {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
}

fn sha1_base64(parts: &[&str]) -> String {
    let mut input = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            input.push('&');
        }
        input.push_str(part);
    }
    let digest = Sha1::digest(input.as_bytes());
    BASE64.encode(digest)
}

fn sha256_base64(bytes: &[u8]) -> String {
    BASE64.encode(Sha256::digest(bytes))
}

fn xiaomi_signature(
    method: &str,
    path: &str,
    params: &BTreeMap<String, String>,
    security: &str,
) -> String {
    let mut parts = Vec::with_capacity(3 + params.len());
    parts.push(method.to_uppercase());
    parts.push(path.to_string());
    parts.extend(params.iter().map(|(name, value)| format!("{name}={value}")));
    parts.push(security.to_string());
    let references = parts.iter().map(String::as_str).collect::<Vec<_>>();
    sha1_base64(&references)
}

fn build_xiaomi_signed_params(
    ssecurity: &str,
    method: &str,
    path: &str,
    mut plaintext: BTreeMap<String, String>,
    nonce: &str,
) -> Result<Vec<(String, String)>> {
    let security_bytes = BASE64
        .decode(ssecurity)
        .context("decode Mi WiFi ssecurity")?;
    let nonce_bytes = BASE64.decode(nonce).context("decode Mi WiFi nonce")?;
    let mut key_material = Vec::with_capacity(security_bytes.len() + nonce_bytes.len());
    key_material.extend_from_slice(&security_bytes);
    key_material.extend_from_slice(&nonce_bytes);
    let security = sha256_base64(&key_material);
    let rc4_key = BASE64
        .decode(&security)
        .context("decode Mi WiFi derived RC4 key")?;
    if rc4_key.len() != 32 {
        anyhow::bail!("Mi WiFi derived RC4 key has an unexpected length");
    }

    let rc4_hash = xiaomi_signature(method, path, &plaintext, &security);
    plaintext.insert("rc4_hash__".to_string(), rc4_hash);

    let mut cipher = Rc4Drop::new(&rc4_key);
    let encrypted = plaintext
        .iter()
        .map(|(name, value)| (name.clone(), BASE64.encode(cipher.apply(value.as_bytes()))))
        .collect::<BTreeMap<_, _>>();
    let signature = xiaomi_signature(method, path, &encrypted, &security);

    let mut form = encrypted.into_iter().collect::<Vec<_>>();
    form.push(("signature".to_string(), signature));
    form.push(("_nonce".to_string(), nonce.to_string()));
    Ok(form)
}

fn build_xiaomi_reboot_form(
    ssecurity: &str,
    router_private_id: &str,
    nonce: &str,
) -> Result<Vec<(String, String)>> {
    build_xiaomi_signed_params(
        ssecurity,
        "POST",
        XIAOMI_REBOOT_PATH,
        BTreeMap::from([
            ("deviceID".to_string(), router_private_id.to_string()),
            ("deviceId".to_string(), router_private_id.to_string()),
            ("routerID".to_string(), router_private_id.to_string()),
        ]),
        nonce,
    )
}

struct Rc4Drop {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4Drop {
    fn new(key: &[u8]) -> Self {
        let mut state = [0_u8; 256];
        for (index, value) in state.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut j = 0_u8;
        for index in 0..256 {
            j = j
                .wrapping_add(state[index])
                .wrapping_add(key[index % key.len()]);
            state.swap(index, j as usize);
        }
        let mut cipher = Self { state, i: 0, j: 0 };
        for _ in 0..1024 {
            let _ = cipher.next_byte();
        }
        cipher
    }

    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        self.state
            [(self.state[self.i as usize] as usize + self.state[self.j as usize] as usize) & 0xff]
    }

    fn apply(&mut self, input: &[u8]) -> Vec<u8> {
        input.iter().map(|byte| byte ^ self.next_byte()).collect()
    }
}

fn form_urlencode(params: &[(String, String)]) -> String {
    fn encode(value: &str) -> String {
        let mut output = String::new();
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                output.push(byte as char);
            } else if byte == b' ' {
                output.push('+');
            } else {
                output.push('%');
                output.push_str(&format!("{byte:02X}"));
            }
        }
        output
    }

    params
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn xiaomi_nonce(time_diff_ms: i64) -> Result<String> {
    let mut nonce = [0_u8; 12];
    fs::File::open("/dev/urandom")?.read_exact(&mut nonce[..8])?;
    let minute = (Utc::now().timestamp_millis() + time_diff_ms) / 60_000;
    nonce[8..].copy_from_slice(&(minute as i32).to_be_bytes());
    Ok(BASE64.encode(nonce))
}

fn prepare_xiaomi_request(
    profile: &XiaomiRemoteConfig,
    tokens: &SessionTokens,
) -> Result<PreparedRequest> {
    let service_token = tokens
        .service_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("Mi WiFi session store has no service token")?;
    let ssecurity = tokens
        .ssecurity
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("Mi WiFi session store has no ssecurity")?;
    let router_private_id = xiaomi_router_private_id(profile, tokens)?;
    let nonce = xiaomi_nonce(tokens.time_diff_ms)?;
    let form = build_xiaomi_reboot_form(ssecurity, router_private_id, &nonce)?;
    let headers = xiaomi_remote_headers(profile, tokens, service_token, true);
    Ok(PreparedRequest {
        method: "POST".to_string(),
        url: format!(
            "{}{}",
            profile.base_url.trim_end_matches('/'),
            XIAOMI_REBOOT_PATH
        ),
        headers,
        body: Some(form_urlencode(&form)),
    })
}

fn xiaomi_remote_headers(
    profile: &XiaomiRemoteConfig,
    tokens: &SessionTokens,
    service_token: &str,
    include_content_type: bool,
) -> BTreeMap<String, String> {
    let mut cookies = tokens.cookies.clone();
    cookies
        .entry("serviceToken".to_string())
        .or_insert_with(|| service_token.to_string());
    for (name, value) in [
        (
            "userId",
            session_value(tokens, tokens.user_id.as_deref(), "userId"),
        ),
        (
            "cUserId",
            session_value(tokens, tokens.c_user_id.as_deref(), "cUserId"),
        ),
        (
            "passToken",
            session_value(tokens, tokens.pass_token.as_deref(), "passToken"),
        ),
    ] {
        if let Some(value) = value {
            cookies.entry(name.to_string()).or_insert(value);
        }
    }
    let cookie_header = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let mut headers = BTreeMap::from([
        ("Cookie".to_string(), cookie_header),
        (
            "MiWiFi-Supported-Compression".to_string(),
            "deflate".to_string(),
        ),
        ("User-Agent".to_string(), profile.user_agent.clone()),
    ]);
    if include_content_type {
        headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
    }
    headers
}

fn prepare_xiaomi_init_info_request(
    profile: &XiaomiRemoteConfig,
    tokens: &SessionTokens,
) -> Result<PreparedRequest> {
    let service_token = tokens
        .service_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("Mi WiFi session store has no service token")?;
    let ssecurity = tokens
        .ssecurity
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("Mi WiFi session store has no ssecurity")?;
    let router_private_id = xiaomi_router_private_id(profile, tokens)?;
    let nonce = xiaomi_nonce(tokens.time_diff_ms)?;
    let params = build_xiaomi_signed_params(
        ssecurity,
        "GET",
        XIAOMI_INIT_INFO_PATH,
        BTreeMap::from([
            ("deviceID".to_string(), router_private_id.to_string()),
            ("deviceId".to_string(), router_private_id.to_string()),
            ("routerID".to_string(), router_private_id.to_string()),
        ]),
        &nonce,
    )?;
    Ok(PreparedRequest {
        method: "GET".to_string(),
        url: append_query(
            &format!(
                "{}{}",
                profile.base_url.trim_end_matches('/'),
                XIAOMI_INIT_INFO_PATH
            ),
            &params,
        ),
        headers: xiaomi_remote_headers(profile, tokens, service_token, false),
        body: None,
    })
}

fn xiaomi_router_private_id<'a>(
    profile: &'a XiaomiRemoteConfig,
    tokens: &'a SessionTokens,
) -> Result<&'a str> {
    profile
        .router_private_id
        .as_deref()
        .or(tokens.router_private_id.as_deref())
        .filter(|value| !value.trim().is_empty())
        .context(
            "Mi WiFi router private ID is missing; store router_private_id in the restricted session file",
        )
}

fn xiaomi_service_id(profile: &XiaomiRemoteConfig) -> &'static str {
    match profile.base_url.as_str() {
        "https://eu.api.miwifi.com" => "xiaoqiang_api_eu",
        "https://in.api.miwifi.com" => "xiaoqiang_api_in",
        _ => "xiaoqiang",
    }
}

fn session_value(tokens: &SessionTokens, field: Option<&str>, cookie_name: &str) -> Option<String> {
    field
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| tokens.cookies.get(cookie_name).cloned())
        .filter(|value| !value.is_empty())
}

fn account_cookie_header(tokens: &SessionTokens) -> Result<String> {
    let user_id = session_value(tokens, tokens.user_id.as_deref(), "userId");
    let c_user_id = session_value(tokens, tokens.c_user_id.as_deref(), "cUserId");
    let pass_token = session_value(tokens, tokens.pass_token.as_deref(), "passToken")
        .context("Mi WiFi session needs passToken; bootstrap it through the authorized emulator")?;
    if user_id.is_none() && c_user_id.is_none() {
        anyhow::bail!(
            "Mi WiFi session needs user_id or c_user_id; bootstrap it through the authorized emulator"
        );
    }

    let mut cookies = BTreeMap::new();
    if let Some(value) = user_id {
        cookies.insert("userId".to_string(), value);
    }
    if let Some(value) = c_user_id {
        cookies.insert("cUserId".to_string(), value);
    }
    cookies.insert("passToken".to_string(), pass_token);
    Ok(cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; "))
}

fn append_query(url: &str, params: &[(String, String)]) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{}", form_urlencode(params))
}

fn prepare_xiaomi_service_login_request(
    profile: &XiaomiRemoteConfig,
    tokens: &SessionTokens,
) -> Result<PreparedRequest> {
    let cookie_header = account_cookie_header(tokens)?;
    let params = vec![
        ("sid".to_string(), xiaomi_service_id(profile).to_string()),
        ("_json".to_string(), "true".to_string()),
    ];
    Ok(PreparedRequest {
        method: "GET".to_string(),
        url: append_query(
            &format!(
                "{}{}",
                profile.account_base_url.trim_end_matches('/'),
                XIAOMI_ACCOUNT_SERVICE_LOGIN_PATH
            ),
            &params,
        ),
        headers: BTreeMap::from([
            ("Cookie".to_string(), cookie_header),
            ("User-Agent".to_string(), profile.user_agent.clone()),
        ]),
        body: None,
    })
}

fn prepare_xiaomi_service_exchange_request(
    profile: &XiaomiRemoteConfig,
    location: &str,
    nonce: i64,
    ssecurity: &str,
    tokens: &SessionTokens,
) -> Result<PreparedRequest> {
    let account_base = profile.account_base_url.trim_end_matches('/');
    let api_base = profile.base_url.trim_end_matches('/');
    let allowed_bases = [account_base, api_base];
    if !allowed_bases
        .iter()
        .any(|base| location.starts_with(&format!("{base}/")))
    {
        anyhow::bail!(
            "Mi WiFi service-login location is outside the configured Xiaomi account/API hosts"
        );
    }
    let nonce_string = nonce.to_string();
    let nonce_part = format!("nonce={nonce_string}");
    let client_sign = sha1_base64(&[nonce_part.as_str(), ssecurity]);
    let params = vec![
        ("clientSign".to_string(), client_sign),
        ("_userIdNeedEncrypt".to_string(), "true".to_string()),
    ];
    Ok(PreparedRequest {
        method: "GET".to_string(),
        url: append_query(location, &params),
        headers: BTreeMap::from([
            ("Cookie".to_string(), account_cookie_header(tokens)?),
            ("User-Agent".to_string(), profile.user_agent.clone()),
        ]),
        body: None,
    })
}

fn xiaomi_login_payload(body: &str) -> Result<Value> {
    let trimmed = body.trim();
    let json = trimmed
        .strip_prefix("&&&START&&&")
        .unwrap_or(trimmed)
        .trim();
    serde_json::from_str(json).context("parse Mi WiFi service-login response")
}

fn substitute(raw: &str, tokens: &SessionTokens) -> String {
    raw.replace("${access_token}", &tokens.access_token)
        .replace(
            "${refresh_token}",
            tokens.refresh_token.as_deref().unwrap_or_default(),
        )
}

fn substitute_json(value: &Value, tokens: &SessionTokens) -> Value {
    match value {
        Value::String(raw) => Value::String(substitute(raw, tokens)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| substitute_json(value, tokens))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), substitute_json(value, tokens)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn prepare_request(template: &RequestTemplate, tokens: &SessionTokens) -> Result<PreparedRequest> {
    template.validate()?;
    let body = template
        .body
        .as_ref()
        .map(|value| serde_json::to_string(&substitute_json(value, tokens)))
        .transpose()?;
    Ok(PreparedRequest {
        method: substitute(&template.method, tokens),
        url: substitute(&template.url, tokens),
        headers: template
            .headers
            .iter()
            .map(|(key, value)| (key.clone(), substitute(value, tokens)))
            .collect(),
        body,
    })
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    body: String,
}

fn run_curl(
    request: &PreparedRequest,
    side_effect: bool,
    tokens: &SessionTokens,
    timeout_seconds: u64,
) -> Result<HttpResponse> {
    let mut command = Command::new("curl");
    let timeout = timeout_seconds.to_string();
    command.args([
        "--silent",
        "--show-error",
        "--include",
        "--config",
        "-",
        "--write-out",
        &format!("{CURL_STATUS_MARKER}%{{http_code}}"),
    ]);

    fn config_quote(value: &str) -> String {
        format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        )
    }

    let mut config = format!(
        "connect-timeout = {timeout}\nmax-time = {timeout}\nrequest = {}\n",
        config_quote(&request.method)
    );
    config.push_str(&format!("url = {}\n", config_quote(&request.url)));
    for (name, value) in &request.headers {
        config.push_str(&format!(
            "header = {}\n",
            config_quote(&format!("{name}: {value}"))
        ));
    }
    if let Some(body) = &request.body {
        config.push_str(&format!("data-binary = {}\n", config_quote(body)));
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("run remote Mi WiFi request")?;
    child
        .stdin
        .take()
        .context("open curl configuration input")?
        .write_all(config.as_bytes())?;
    let output = child
        .wait_with_output()
        .context("wait for remote Mi WiFi request")?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        if side_effect {
            return Ok(HttpResponse {
                status: 0,
                headers: BTreeMap::new(),
                body: format!(
                    "ambiguous transport failure: {}",
                    redact_text_with_tokens(&error, tokens)
                ),
            });
        }
        anyhow::bail!(
            "remote authentication request failed: {}",
            redact_text_with_tokens(&error, tokens)
        );
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let Some((raw_response, status)) = raw.rsplit_once(CURL_STATUS_MARKER) else {
        anyhow::bail!("remote request returned no HTTP status");
    };
    let status = status
        .trim()
        .parse::<u16>()
        .context("parse remote HTTP status")?;
    let (header_text, body) = raw_response
        .split_once("\r\n\r\n")
        .or_else(|| raw_response.split_once("\n\n"))
        .unwrap_or(("", raw_response));
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    for line in header_text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers
                .entry(name.trim().to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body: body.to_string(),
    })
}

fn redact_text(raw: &str) -> String {
    let mut output = raw.replace("${access_token}", "[redacted]");
    for marker in [
        "access_token",
        "refresh_token",
        "serviceToken",
        "ssecurity",
        "Authorization",
        "authorization",
    ] {
        output = output.replace(marker, "[redacted-field]");
    }
    output.trim().chars().take(240).collect()
}

fn redact_text_with_tokens(raw: &str, tokens: &SessionTokens) -> String {
    let mut output = raw.to_string();
    for secret in [
        Some(tokens.access_token.as_str()),
        tokens.refresh_token.as_deref(),
        tokens.service_token.as_deref(),
        tokens.ssecurity.as_deref(),
        tokens.user_id.as_deref(),
        tokens.c_user_id.as_deref(),
        tokens.pass_token.as_deref(),
        tokens.router_private_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|secret| !secret.is_empty())
    {
        output = output.replace(secret, "[redacted]");
    }
    for secret in tokens.cookies.values().filter(|secret| !secret.is_empty()) {
        output = output.replace(secret, "[redacted]");
    }
    redact_text(&output)
}

pub struct ConfiguredRemoteClient {
    config: WatchdogConfig,
    token_file: PathBuf,
    repo_root: Option<PathBuf>,
    env: HashMap<String, String>,
}

impl ConfiguredRemoteClient {
    pub fn new(config: WatchdogConfig) -> Self {
        let token_file = config.resolved_token_file();
        Self {
            config,
            token_file,
            repo_root: None,
            env: HashMap::new(),
        }
    }

    fn with_context(config: WatchdogConfig, context: &ModuleContext) -> Self {
        let mut client = Self::new(config);
        client.repo_root = Some(context.repo_root.clone());
        client.env = context.env.clone();
        client
    }

    fn load_tokens(&self) -> Result<SessionTokens> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = fs::symlink_metadata(&self.token_file).with_context(|| {
                format!(
                    "inspect Mi WiFi session store {}",
                    self.token_file.to_string_lossy()
                )
            })?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("Mi WiFi session store must not be a symbolic link");
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(&self.token_file, fs::Permissions::from_mode(0o600))
                    .context("restrict Mi WiFi session store permissions")?;
            }
        }
        let raw = fs::read_to_string(&self.token_file).with_context(|| {
            format!(
                "read Mi WiFi session store {}",
                self.token_file.to_string_lossy()
            )
        })?;
        let tokens: SessionTokens =
            serde_json::from_str(&raw).context("parse Mi WiFi session store")?;
        if tokens.access_token.trim().is_empty()
            && tokens
                .service_token
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            && tokens.pass_token.as_deref().unwrap_or_default().is_empty()
        {
            anyhow::bail!("Mi WiFi session store has no usable credential");
        }
        Ok(tokens)
    }

    fn save_tokens(&self, tokens: &SessionTokens) -> Result<()> {
        if let Some(parent) = self.token_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(tokens)?;
        let temporary = self.token_file.with_extension(format!(
            "{}-{}.tmp",
            std::process::id(),
            Utc::now().timestamp_micros()
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(&data)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.token_file)?;
            if let Some(parent) = self.token_file.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn refresh(&self, tokens: &mut SessionTokens) -> Result<()> {
        let Some(template) = &self.config.remote.refresh else {
            anyhow::bail!("Mi WiFi access token expired and no refresh request is configured");
        };
        if tokens
            .refresh_token
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        {
            anyhow::bail!("Mi WiFi session store has no refresh token");
        }
        let request = prepare_request(template, tokens)?;
        let response = run_curl(&request, false, tokens, self.config.remote.timeout_seconds)?;
        if !template.success_statuses().contains(&response.status) {
            anyhow::bail!(
                "Mi WiFi token refresh rejected with HTTP {}",
                response.status
            );
        }
        let payload: Value =
            serde_json::from_str(&response.body).context("parse Mi WiFi token refresh response")?;
        let access = payload
            .get(&self.config.remote.access_token_field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("Mi WiFi token refresh response has no access token")?;
        tokens.access_token = access.to_string();
        if let Some(refresh) = payload
            .get(&self.config.remote.refresh_token_field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            tokens.refresh_token = Some(refresh.to_string());
        }
        if let Some(expires_at) = payload
            .get(&self.config.remote.expires_at_field)
            .and_then(Value::as_i64)
        {
            tokens.expires_at = Some(expires_at);
        }
        self.save_tokens(tokens)
    }

    fn can_refresh_xiaomi(tokens: &SessionTokens) -> bool {
        (session_value(tokens, tokens.user_id.as_deref(), "userId").is_some()
            || session_value(tokens, tokens.c_user_id.as_deref(), "cUserId").is_some())
            && session_value(tokens, tokens.pass_token.as_deref(), "passToken").is_some()
    }

    fn can_collect_xiaomi(&self) -> bool {
        self.repo_root.is_some()
    }

    fn refresh_or_collect_xiaomi(
        &self,
        profile: &XiaomiRemoteConfig,
        tokens: &mut SessionTokens,
    ) -> Result<()> {
        if Self::can_refresh_xiaomi(tokens) {
            match self.refresh_xiaomi(profile, tokens) {
                Ok(()) => return Ok(()),
                Err(error) if !self.can_collect_xiaomi() => return Err(error),
                Err(_) => {}
            }
        }
        if !self.can_collect_xiaomi() {
            anyhow::bail!(
                "Mi WiFi service-token expiry is required or stale; bootstrap user/pass credentials through the authorized emulator"
            );
        }
        let router_private_id = tokens
            .router_private_id
            .clone()
            .or_else(|| profile.router_private_id.clone());
        let mut collected = self.collect_xiaomi_session(profile)?;
        if collected.router_private_id.is_none() && router_private_id.is_some() {
            collected.router_private_id = router_private_id;
            self.save_tokens(&collected)?;
        }
        *tokens = collected;
        Ok(())
    }

    fn refresh_xiaomi(
        &self,
        profile: &XiaomiRemoteConfig,
        tokens: &mut SessionTokens,
    ) -> Result<()> {
        let login_request = prepare_xiaomi_service_login_request(profile, tokens)?;
        let login_response = run_curl(
            &login_request,
            false,
            tokens,
            self.config.remote.timeout_seconds,
        )?;
        if !(200..300).contains(&login_response.status) {
            anyhow::bail!(
                "Mi WiFi service-token refresh rejected with HTTP {}",
                login_response.status
            );
        }
        let login_payload = xiaomi_login_payload(&login_response.body)?;
        if login_payload
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or(-1)
            != 0
        {
            anyhow::bail!("Mi WiFi service-token refresh returned an account error");
        }
        let ssecurity = login_payload
            .get("ssecurity")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("Mi WiFi refresh response has no ssecurity")?;
        let location = login_payload
            .get("location")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("Mi WiFi refresh response has no service-token location")?;
        let nonce = login_payload
            .get("nonce")
            .and_then(Value::as_i64)
            .context("Mi WiFi refresh response has no nonce")?;
        let exchange_request =
            prepare_xiaomi_service_exchange_request(profile, location, nonce, ssecurity, tokens)?;
        let exchange_response = run_curl(
            &exchange_request,
            false,
            tokens,
            self.config.remote.timeout_seconds,
        )?;
        if !(200..300).contains(&exchange_response.status) {
            anyhow::bail!(
                "Mi WiFi service-token exchange rejected with HTTP {}",
                exchange_response.status
            );
        }
        let service_token = exchange_response
            .headers
            .get("set-cookie")
            .into_iter()
            .flatten()
            .filter_map(|header| header.split(';').next())
            .filter_map(|cookie| cookie.split_once('='))
            .find_map(|(name, value)| {
                (name.trim() == "serviceToken" && !value.trim().is_empty())
                    .then(|| value.trim().to_string())
            })
            .context("Mi WiFi service-token exchange returned no serviceToken cookie")?;

        tokens.service_token = Some(service_token.clone());
        tokens.ssecurity = Some(ssecurity.to_string());
        tokens
            .cookies
            .insert("serviceToken".to_string(), service_token);
        tokens.expires_at = Some(Utc::now().timestamp() + 86_400);
        if let Some(date) = login_response
            .headers
            .get("date")
            .and_then(|values| values.first())
        {
            if let Ok(server_date) = DateTime::parse_from_rfc2822(date) {
                tokens.time_diff_ms =
                    server_date.timestamp_millis() - Utc::now().timestamp_millis();
            }
        }
        self.save_tokens(tokens)
    }

    fn token_is_expired(tokens: &SessionTokens) -> bool {
        tokens
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now().timestamp() + 30)
    }

    fn preflight_xiaomi(
        &self,
        profile: &XiaomiRemoteConfig,
        tokens: &mut SessionTokens,
    ) -> Result<u16> {
        let mut request = prepare_xiaomi_init_info_request(profile, tokens)?;
        let mut response = run_curl(&request, false, tokens, self.config.remote.timeout_seconds)?;
        if response.status == 401 {
            self.refresh_or_collect_xiaomi(profile, tokens)?;
            request = prepare_xiaomi_init_info_request(profile, tokens)?;
            response = run_curl(&request, false, tokens, self.config.remote.timeout_seconds)?;
        }
        if !(200..300).contains(&response.status) {
            let detail = redact_text_with_tokens(&response.body, tokens);
            anyhow::bail!(
                "Mi WiFi authenticated preflight rejected with HTTP {}: {}",
                response.status,
                if detail.is_empty() {
                    "no response detail"
                } else {
                    detail.as_str()
                }
            );
        }
        Ok(response.status)
    }
}

impl RemoteRebooter for ConfiguredRemoteClient {
    fn reboot(&mut self) -> Result<RemoteCallOutcome> {
        if !self.config.verified_remote_api {
            anyhow::bail!(
                "Mi WiFi remote API is disabled until static and dynamic evidence verifies the request profile"
            );
        }
        let xiaomi_profile = self.config.remote.xiaomi.clone();
        let mut tokens = match self.load_tokens() {
            Ok(tokens) => tokens,
            Err(_error) if xiaomi_profile.is_some() && self.can_collect_xiaomi() => {
                self.collect_xiaomi_session(xiaomi_profile.as_ref().expect("profile"))?
            }
            Err(error) => return Err(error),
        };
        let (mut request, success_statuses) = if let Some(profile) = xiaomi_profile.as_ref() {
            if tokens.expires_at.is_none() || Self::token_is_expired(&tokens) {
                self.refresh_or_collect_xiaomi(profile, &mut tokens)?;
            }
            self.preflight_xiaomi(profile, &mut tokens)?;
            (
                prepare_xiaomi_request(profile, &tokens)?,
                profile.success_statuses().to_vec(),
            )
        } else {
            let template = self
                .config
                .remote
                .reboot
                .as_ref()
                .context("Mi WiFi reboot request profile is missing")?;
            if Self::token_is_expired(&tokens) {
                self.refresh(&mut tokens)?;
            }
            (
                prepare_request(template, &tokens)?,
                template.success_statuses().to_vec(),
            )
        };

        let mut response = run_curl(&request, true, &tokens, self.config.remote.timeout_seconds)?;
        if response.status == 401 {
            if let Some(profile) = xiaomi_profile.as_ref() {
                self.refresh_or_collect_xiaomi(profile, &mut tokens)?;
                request = prepare_xiaomi_request(profile, &tokens)?;
                response = run_curl(&request, true, &tokens, self.config.remote.timeout_seconds)?;
            }
        }
        if response.status == 0 {
            return Ok(RemoteCallOutcome::Ambiguous {
                reason: redact_text_with_tokens(&response.body, &tokens),
            });
        }
        if success_statuses.contains(&response.status) {
            return Ok(RemoteCallOutcome::Accepted {
                status: response.status,
            });
        }
        Ok(RemoteCallOutcome::Rejected {
            status: response.status,
        })
    }
}

fn read_config(context: &ModuleContext) -> Result<WatchdogConfig> {
    let path = context.module_dir.join("module.yaml");
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read miwatch config {}", path.display()))?;
    let config: WatchdogConfig = serde_yaml::from_str(&raw).context("parse miwatch config")?;
    config.validate()?;
    Ok(config)
}

fn load_state(path: &Path) -> Result<WatchdogState> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WatchdogState::default());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read miwatch state {}", path.display()));
        }
    };
    serde_json::from_str(&raw).with_context(|| format!("parse miwatch state {}", path.display()))
}

fn save_state(path: &Path, state: &WatchdogState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn outcome_message(outcome: &TickOutcome) -> &'static str {
    match outcome {
        TickOutcome::Cooldown => "cooldown active",
        TickOutcome::AlreadyAttempted => "reboot already attempted for incident",
        TickOutcome::RebootAccepted { .. } => "remote reboot accepted",
        TickOutcome::RebootRejected { .. } => "remote reboot rejected",
        TickOutcome::RebootAmbiguous => "remote reboot result ambiguous; suppressing retry",
    }
}

static STATE: once_cell::sync::Lazy<std::sync::Mutex<Option<ModuleStatus>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

pub fn refresh_session(context: &mut ModuleContext) -> Result<()> {
    let config = read_config(context)?;
    let profile = config
        .remote
        .xiaomi
        .clone()
        .context("miwatch remote.xiaomi profile is required for session refresh")?;
    profile.validate()?;
    let client = ConfiguredRemoteClient::new(config);
    let mut tokens = client.load_tokens()?;
    client.refresh_xiaomi(&profile, &mut tokens)?;
    context.logger.info(&format!(
        "Mi WiFi session refreshed; expires_at={}",
        tokens.expires_at.unwrap_or_default()
    ));
    Ok(())
}

/// Validates the authenticated Xiaomi remote route without issuing a reboot.
pub fn verify_remote(context: &mut ModuleContext) -> Result<()> {
    let config = read_config(context)?;
    let profile = config
        .remote
        .xiaomi
        .clone()
        .context("miwatch remote.xiaomi profile is required for remote verification")?;
    profile.validate()?;
    let client = ConfiguredRemoteClient::with_context(config, context);
    let mut tokens = match client.load_tokens() {
        Ok(tokens) => tokens,
        Err(_) if client.can_collect_xiaomi() => client.collect_xiaomi_session(&profile)?,
        Err(error) => return Err(error),
    };
    if tokens.expires_at.is_none() || ConfiguredRemoteClient::token_is_expired(&tokens) {
        client.refresh_or_collect_xiaomi(&profile, &mut tokens)?;
    }
    let status = client.preflight_xiaomi(&profile, &mut tokens)?;
    context.logger.info(&format!(
        "Mi WiFi authenticated preflight succeeded with HTTP {status}"
    ));
    println!("Mi WiFi authenticated preflight succeeded with HTTP {status}");
    Ok(())
}

pub fn import_session(context: &mut ModuleContext, input: &str) -> Result<()> {
    let config = read_config(context)?;
    let tokens: SessionTokens =
        serde_json::from_str(input).context("parse Mi WiFi bootstrap JSON")?;
    if !ConfiguredRemoteClient::can_refresh_xiaomi(&tokens) {
        anyhow::bail!("Mi WiFi bootstrap JSON needs user_id or c_user_id plus pass_token");
    }
    let client = ConfiguredRemoteClient::new(config);
    client.save_tokens(&tokens)?;
    context
        .logger
        .info("Mi WiFi emulator bootstrap imported into the restricted session store");
    Ok(())
}

impl ConfiguredRemoteClient {
    fn collect_xiaomi_session(&self, profile: &XiaomiRemoteConfig) -> Result<SessionTokens> {
        let repo_root = self
            .repo_root
            .as_ref()
            .context("Mi WiFi emulator collection requires a module context")?;
        let collector_source = repo_root.join("tools/miwatch-emulator/MiwatchCollector.java");
        if !collector_source.is_file() {
            anyhow::bail!("miwatch emulator collector source is missing");
        }

        let sdk_root = self
            .env
            .get("ANDROID_HOME")
            .or_else(|| self.env.get("ANDROID_SDK_ROOT"))
            .cloned()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("/"))
                    .join("Library/Android/sdk")
            });
        let android_jar = sdk_root.join("platforms/android-34/android.jar");
        let d8 = self
            .env
            .get("D8")
            .map(PathBuf::from)
            .unwrap_or_else(|| sdk_root.join("build-tools/34.0.0/d8"));
        let javac = self
            .env
            .get("JAVAC")
            .map(PathBuf::from)
            .or_else(|| {
                self.env
                    .get("JAVA_HOME")
                    .map(|home| PathBuf::from(home).join("bin/javac"))
            })
            .unwrap_or_else(|| {
                let homebrew_javac = PathBuf::from("/opt/homebrew/opt/openjdk/bin/javac");
                if homebrew_javac.is_file() {
                    homebrew_javac
                } else {
                    PathBuf::from("javac")
                }
            });
        let java_home = self.env.get("JAVA_HOME").cloned().or_else(|| {
            Path::new("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home")
                .is_dir()
                .then(|| "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home".to_string())
        });
        let adb = self
            .env
            .get("ADB")
            .cloned()
            .unwrap_or_else(|| "adb".to_string());
        for required in [&android_jar, &d8] {
            if !required.is_file() {
                anyhow::bail!(
                    "miwatch emulator collector dependency is missing: {}",
                    required.display()
                );
            }
        }

        let temp_root = std::env::temp_dir().join(format!(
            "miwatch-collector-{}-{}",
            std::process::id(),
            Utc::now().timestamp_micros()
        ));
        fs::create_dir(&temp_root)?;
        fs::create_dir(temp_root.join("classes"))?;
        fs::create_dir(temp_root.join("dex"))?;
        let result = collect_session_from_emulator(
            &adb,
            &javac,
            &d8,
            &android_jar,
            &collector_source,
            &temp_root,
            java_home.as_deref(),
            self.env.get("PATH").map(String::as_str),
        )
        .and_then(|mut tokens| {
            if !ConfiguredRemoteClient::can_refresh_xiaomi(&tokens) {
                anyhow::bail!("emulator collector returned no usable Xiaomi account credentials");
            }
            if tokens.router_private_id.is_none() {
                tokens.router_private_id = profile.router_private_id.clone();
            }
            if tokens
                .service_token
                .as_deref()
                .unwrap_or_default()
                .is_empty()
                || tokens.ssecurity.as_deref().unwrap_or_default().is_empty()
            {
                self.save_tokens(&tokens)?;
                self.refresh_xiaomi(profile, &mut tokens)?;
            } else {
                let service_token = tokens.service_token.clone().unwrap_or_default();
                tokens
                    .cookies
                    .entry("serviceToken".to_string())
                    .or_insert(service_token);
                if tokens.expires_at.is_none() {
                    tokens.expires_at = Some(Utc::now().timestamp() + 86_400);
                }
                self.save_tokens(&tokens)?;
            }
            Ok(tokens)
        });
        let _ = fs::remove_dir_all(&temp_root);
        result
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_session_from_emulator(
    adb: &str,
    javac: &Path,
    d8: &Path,
    android_jar: &Path,
    collector_source: &Path,
    temp_root: &Path,
    java_home: Option<&str>,
    inherited_path: Option<&str>,
) -> Result<SessionTokens> {
    let classes = temp_root.join("classes");
    let dex_dir = temp_root.join("dex");
    let compile = Command::new(javac)
        .args([
            "-source",
            "8",
            "-target",
            "8",
            "-classpath",
            &android_jar.to_string_lossy(),
            "-d",
            &classes.to_string_lossy(),
            &collector_source.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("compile miwatch emulator collector")?;
    if !compile.success() {
        anyhow::bail!("miwatch emulator collector compilation failed");
    }

    let class_files = fs::read_dir(&classes)?
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "class")
        })
        .collect::<Vec<_>>();
    if class_files.is_empty() {
        anyhow::bail!("miwatch emulator collector produced no class files");
    }
    let mut dex_command = Command::new(d8);
    if let Some(java_home) = java_home {
        dex_command.env("JAVA_HOME", java_home);
        let path = inherited_path.unwrap_or_default();
        dex_command.env("PATH", format!("{java_home}/bin:{path}"));
    }
    dex_command.args([
        "--lib",
        &android_jar.to_string_lossy(),
        "--output",
        &dex_dir.to_string_lossy(),
    ]);
    dex_command.args(class_files.iter().map(|path| path.as_os_str()));
    let dex = dex_command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("build miwatch emulator collector dex")?;
    if !dex.success() {
        anyhow::bail!("miwatch emulator collector dex build failed");
    }
    let dex_path = dex_dir.join("classes.dex");

    run_adb(adb, ["wait-for-device"])?;
    run_adb(adb, ["root"])?;
    run_adb(adb, ["wait-for-device"])?;
    let identity = Command::new(adb)
        .args(["shell", "id"])
        .output()
        .context("check miwatch emulator adb identity")?;
    if !String::from_utf8_lossy(&identity.stdout).contains("uid=0") {
        anyhow::bail!("miwatch emulator collector requires an adb-root AVD");
    }
    run_adb(
        adb,
        ["push", &dex_path.to_string_lossy(), EMULATOR_COLLECTOR_DEX],
    )?;

    let command =
        format!("CLASSPATH={EMULATOR_COLLECTOR_DEX} app_process64 /system/bin MiwatchCollector");
    let output = Command::new(adb).args(["exec-out", &command]).output();
    let _ = Command::new(adb)
        .args(["shell", "rm", "-f", EMULATOR_COLLECTOR_DEX])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let output = output.context("run miwatch emulator collector")?;
    if !output.status.success() {
        anyhow::bail!("miwatch emulator collector failed; complete Xiaomi login first");
    }
    serde_json::from_slice(&output.stdout).context("parse miwatch emulator collector JSON")
}

fn run_adb<const N: usize>(adb: &str, args: [&str; N]) -> Result<()> {
    let status = Command::new(adb)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("run adb for miwatch emulator collector")?;
    if !status.success() {
        anyhow::bail!("adb failed during miwatch emulator collection");
    }
    Ok(())
}

pub fn setup(_context: &mut ModuleContext) -> Result<()> {
    Ok(())
}

pub fn run_once(context: &mut ModuleContext) -> Result<Option<ModuleStatus>> {
    let config = read_config(context)?;
    let now = Utc::now();
    let state_path = config.resolved_state_file();
    let mut state = load_state(&state_path)?;
    let incident_id = match &context.invocation {
        ModuleInvocation::Trigger(invocation) => invocation.incident_id.clone(),
        ModuleInvocation::Manual => format!("manual:{}", now.timestamp_millis()),
    };

    let mut rebooter = ConfiguredRemoteClient::with_context(config.clone(), context);
    let outcome = execute_incident(
        &mut state,
        &config,
        &incident_id,
        now,
        &state_path,
        &mut rebooter,
    )?;

    let message = outcome_message(&outcome);
    context.logger.info(&format!(
        "incident={}; source={}; outcome={}",
        incident_id,
        match &context.invocation {
            ModuleInvocation::Manual => "manual",
            ModuleInvocation::Trigger(_) => "trigger",
        },
        message,
    ));
    let status = ModuleStatus {
        state: "running".to_string(),
        message: Some(message.to_string()),
        started_at: None,
        last_run_at: Some(now.to_rfc3339()),
        next_run_at: None,
        metrics: Some(HashMap::from([
            ("attempted".to_string(), Value::Bool(state.reboot_attempted)),
            (
                "incidentGeneration".to_string(),
                Value::from(
                    state
                        .last_incident_id
                        .as_deref()
                        .and_then(|value| value.rsplit_once(':'))
                        .and_then(|(_, generation)| generation.parse::<u64>().ok())
                        .unwrap_or_default(),
                ),
            ),
        ])),
    };
    if let Ok(mut current) = STATE.lock() {
        *current = Some(status.clone());
    }
    Ok(Some(status))
}

pub fn status() -> Option<(ModuleStatus, ModuleHealth)> {
    STATE.lock().ok().and_then(|value| {
        value.clone().map(|status| {
            (
                status,
                ModuleHealth {
                    ok: true,
                    message: Some("watchdog state available".to_string()),
                },
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use tempfile::tempdir;

    struct FakeRebooter {
        calls: usize,
        outcome: RemoteCallOutcome,
    }

    impl RemoteRebooter for FakeRebooter {
        fn reboot(&mut self) -> Result<RemoteCallOutcome> {
            self.calls += 1;
            Ok(self.outcome.clone())
        }
    }

    struct PersistCheckingRebooter {
        state_path: PathBuf,
        calls: usize,
        fail_after_observation: bool,
    }

    impl RemoteRebooter for PersistCheckingRebooter {
        fn reboot(&mut self) -> Result<RemoteCallOutcome> {
            self.calls += 1;
            let persisted = load_state(&self.state_path).expect("persisted attempt state");
            assert!(persisted.reboot_attempted);
            assert_eq!(persisted.last_outcome.as_deref(), Some("attempt_started"));
            if self.fail_after_observation {
                anyhow::bail!("simulated crash boundary");
            }
            Ok(RemoteCallOutcome::Accepted { status: 200 })
        }
    }

    struct MockResponse {
        status: Option<u16>,
        body: String,
        headers: Vec<(String, String)>,
    }

    struct MockServer {
        address: String,
        requests: Arc<Mutex<Vec<String>>>,
        handle: Option<JoinHandle<()>>,
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("mock server thread");
            }
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let count = stream.read(&mut chunk).expect("read mock request");
            if count == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..count]);
            let Some(header_end) = buffer.windows(4).position(|value| value == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&buffer[..header_end]);
            let content_length = headers.lines().find_map(|line| {
                line.strip_prefix("Content-Length:")
                    .or_else(|| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
            });
            let body_len = buffer.len().saturating_sub(header_end + 4);
            if body_len >= content_length.unwrap_or(0) {
                break;
            }
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }

    fn spawn_mock_server(responses: Vec<MockResponse>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().unwrap().to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let response_address = address.clone();
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept mock request");
                let request = read_http_request(&mut stream);
                recorded.lock().unwrap().push(request);
                let Some(status) = response.status else {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                let reason = match status {
                    200 => "OK",
                    202 => "Accepted",
                    429 => "Too Many Requests",
                    _ => "Response",
                };
                let rendered_body = response.body.replace("{address}", &response_address);
                let body = rendered_body.as_bytes();
                let mut header = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (name, value) in response.headers {
                    header.push_str(&format!("{name}: {value}\r\n"));
                }
                header.push_str("\r\n");
                stream
                    .write_all(header.as_bytes())
                    .expect("write mock headers");
                stream.write_all(body).expect("write mock body");
            }
        });
        MockServer {
            address,
            requests,
            handle: Some(handle),
        }
    }

    fn request_template(url: String, body: Value, success_statuses: Vec<u16>) -> RequestTemplate {
        RequestTemplate {
            method: "POST".to_string(),
            url,
            headers: BTreeMap::from([
                (
                    "Authorization".to_string(),
                    "Bearer ${access_token}".to_string(),
                ),
                ("Content-Type".to_string(), "application/json".to_string()),
            ]),
            body: Some(body),
            success_statuses,
        }
    }

    fn config() -> WatchdogConfig {
        WatchdogConfig {
            cooldown_seconds: 60,
            ..WatchdogConfig::default()
        }
    }

    #[test]
    fn legacy_module_policy_requires_top_level_trigger_migration() {
        let config: WatchdogConfig = serde_yaml::from_str(
            r#"
ssid: old-network
timezone: Asia/Dhaka
window_start: "05:00"
window_end: "02:00"
failure_threshold: 3
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("moved to top-level triggers"));
    }

    #[test]
    fn cooldown_state_survives_restart_and_blocks_new_attempt() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("watchdog-state.json");
        let now = Utc::now();
        let saved = WatchdogState {
            reboot_attempted: false,
            last_reboot_at: Some(now.to_rfc3339()),
            cooldown_until: Some((now + Duration::seconds(60)).to_rfc3339()),
            last_outcome: Some("reboot_accepted".to_string()),
            last_incident_id: None,
            attempt_started_at: None,
        };
        save_state(&state_path, &saved).unwrap();
        let mut state = load_state(&state_path).expect("persisted cooldown state");
        let mut rebooter = FakeRebooter {
            calls: 0,
            outcome: RemoteCallOutcome::Accepted { status: 202 },
        };
        assert_eq!(
            execute_incident(
                &mut state,
                &config(),
                "miwatch-outage:8",
                now + Duration::seconds(1),
                &state_path,
                &mut rebooter
            )
            .unwrap(),
            TickOutcome::Cooldown
        );
        assert_eq!(rebooter.calls, 0);
    }

    #[test]
    fn incident_attempt_is_persisted_before_request_and_error_cannot_redispatch() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("watchdog-state.json");
        let now = Utc::now();
        let mut state = WatchdogState::default();
        let mut first = PersistCheckingRebooter {
            state_path: state_path.clone(),
            calls: 0,
            fail_after_observation: true,
        };
        assert!(execute_incident(
            &mut state,
            &config(),
            "miwatch-outage:7",
            now,
            &state_path,
            &mut first,
        )
        .is_err());
        assert_eq!(first.calls, 1);

        let mut restored = load_state(&state_path).expect("persisted incident state");
        let mut second = PersistCheckingRebooter {
            state_path: state_path.clone(),
            calls: 0,
            fail_after_observation: false,
        };
        assert_eq!(
            execute_incident(
                &mut restored,
                &config(),
                "miwatch-outage:7",
                now + Duration::seconds(1),
                &state_path,
                &mut second,
            )
            .unwrap(),
            TickOutcome::AlreadyAttempted
        );
        assert_eq!(second.calls, 0);
    }

    #[test]
    fn malformed_watchdog_state_fails_closed() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("watchdog-state.json");
        fs::write(&state_path, "{not-json").unwrap();

        let error = load_state(&state_path).expect_err("malformed state must not reset");

        assert!(error.to_string().contains("parse miwatch state"));
    }

    #[test]
    fn request_template_substitutes_tokens_without_logging_them() {
        let template = RequestTemplate {
            method: "POST".to_string(),
            url: "https://example.invalid/${access_token}".to_string(),
            headers: BTreeMap::from([(
                "Authorization".to_string(),
                "Bearer ${access_token}".to_string(),
            )]),
            body: Some(serde_json::json!({ "refresh": "${refresh_token}" })),
            success_statuses: vec![200],
        };
        let tokens = SessionTokens {
            access_token: "access-secret".to_string(),
            refresh_token: Some("refresh-secret".to_string()),
            expires_at: None,
            ..Default::default()
        };
        let prepared = prepare_request(&template, &tokens).unwrap();
        assert_eq!(prepared.url, "https://example.invalid/access-secret");
        assert_eq!(prepared.headers["Authorization"], "Bearer access-secret");
        assert_eq!(prepared.body.unwrap(), r#"{"refresh":"refresh-secret"}"#);
        let log = redact_text_with_tokens("Authorization access-secret refresh-secret", &tokens);
        assert!(!log.contains("access-secret"));
        assert!(!log.contains("refresh-secret"));
    }

    #[test]
    fn xiaomi_signed_reboot_form_matches_apk_protocol_vector() {
        let form = build_xiaomi_reboot_form(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "router-private-123",
            "ICEiIyQlJicoKSor",
        )
        .unwrap();

        assert_eq!(
            form,
            vec![
                (
                    "deviceID".to_string(),
                    "R8kDmyhq1LdC5ndscXoycz30".to_string()
                ),
                (
                    "deviceId".to_string(),
                    "mpXbi7POMOs6dY+bRh3x8Npf".to_string()
                ),
                (
                    "rc4_hash__".to_string(),
                    "PJ2idiIS94ncxttXXQvJSHH/Hw5cPItSzrIMDA==".to_string()
                ),
                (
                    "routerID".to_string(),
                    "4MYK936ngyshjRep2gKGm7Wq".to_string()
                ),
                (
                    "signature".to_string(),
                    "Ij0ry/TTrXY+FvNRN9/8C/1fM5o=".to_string()
                ),
                ("_nonce".to_string(), "ICEiIyQlJicoKSor".to_string()),
            ]
        );
    }

    #[test]
    fn xiaomi_form_matches_captured_apk_wire_fixture() {
        let form = build_xiaomi_reboot_form(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "router-private-123",
            "PlwfbD32TO4Bxgj+",
        )
        .unwrap();

        assert_eq!(
            form,
            vec![
                (
                    "deviceID".to_string(),
                    "QyxFSbhWXD2yS75cUoXQuMfO".to_string()
                ),
                (
                    "deviceId".to_string(),
                    "8VHDuGF9RA/gC4Qb688+MJ18".to_string()
                ),
                (
                    "rc4_hash__".to_string(),
                    "jzNzK5K2bXFV/5fNPSoy3TkJgBciL47mtPGsOA==".to_string()
                ),
                (
                    "routerID".to_string(),
                    "ZiD5DG6kuMOCPIOhWMyDbudc".to_string()
                ),
                (
                    "signature".to_string(),
                    "J4w16de1rg27JNqLMO2OOdNKX/U=".to_string()
                ),
                ("_nonce".to_string(), "PlwfbD32TO4Bxgj+".to_string()),
            ]
        );
        assert_eq!(
            form_urlencode(&form),
            "deviceID=QyxFSbhWXD2yS75cUoXQuMfO&deviceId=8VHDuGF9RA%2FgC4Qb688%2BMJ18&rc4_hash__=jzNzK5K2bXFV%2F5fNPSoy3TkJgBciL47mtPGsOA%3D%3D&routerID=ZiD5DG6kuMOCPIOhWMyDbudc&signature=J4w16de1rg27JNqLMO2OOdNKX%2FU%3D&_nonce=PlwfbD32TO4Bxgj%2B"
        );
    }

    #[test]
    fn router_private_id_can_live_only_in_the_restricted_session() {
        let profile = XiaomiRemoteConfig {
            base_url: "https://api.miwifi.com".to_string(),
            account_base_url: "https://account.xiaomi.com".to_string(),
            router_private_id: None,
            user_agent: "Android APP/com.xiaomi.router APPV/5.9.0".to_string(),
            success_statuses: vec![200],
        };
        let tokens = SessionTokens {
            router_private_id: Some("router-private-123".to_string()),
            ..SessionTokens::default()
        };

        assert_eq!(
            xiaomi_router_private_id(&profile, &tokens).unwrap(),
            "router-private-123"
        );
        assert!(xiaomi_router_private_id(&profile, &SessionTokens::default()).is_err());
    }

    #[test]
    fn xiaomi_profile_requires_expiry_metadata() {
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("xiaomi-session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                access_token: String::new(),
                service_token: Some("service-secret".to_string()),
                ssecurity: Some(BASE64.encode([7_u8; 32])),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.xiaomi = Some(XiaomiRemoteConfig {
            base_url: "https://api.miwifi.com".to_string(),
            account_base_url: "https://account.xiaomi.com".to_string(),
            router_private_id: Some("router-private-123".to_string()),
            user_agent: "Android APP/com.xiaomi.router APPV/5.9.0".to_string(),
            success_statuses: vec![200],
        });

        let mut client = ConfiguredRemoteClient::new(config);
        let error = client
            .reboot()
            .expect_err("Xiaomi profile must require expiry metadata");
        assert!(error.to_string().contains("expiry is required"));
    }

    #[test]
    fn unverified_remote_profile_fails_closed_before_loading_tokens() {
        let config = WatchdogConfig::default();
        let mut client = ConfiguredRemoteClient::new(config);
        let error = client
            .reboot()
            .expect_err("unverified profile must be rejected");
        assert!(error
            .to_string()
            .contains("disabled until static and dynamic evidence"));
    }

    #[test]
    fn verified_config_requires_exact_xiaomi_profile() {
        let mut config = WatchdogConfig::default();
        config.verified_remote_api = true;
        config.remote.reboot = Some(RequestTemplate {
            method: "POST".to_string(),
            url: "https://example.invalid/reboot".to_string(),
            headers: BTreeMap::new(),
            body: None,
            success_statuses: vec![200],
        });
        let error = config
            .validate()
            .expect_err("generic request templates must not enable Xiaomi reboot");
        assert!(error.to_string().contains("exact Xiaomi request profile"));
    }

    #[test]
    fn session_store_is_written_with_restricted_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("session.json");
        fs::write(&path, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut config = config();
        config.token_file = path.to_string_lossy().to_string();
        let client = ConfiguredRemoteClient::new(config);
        let tokens = SessionTokens {
            access_token: "a".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at: None,
            ..Default::default()
        };
        client.save_tokens(&tokens).unwrap();
        assert_eq!(
            serde_json::from_str::<SessionTokens>(&fs::read_to_string(&path).unwrap()).unwrap(),
            tokens
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with("session.") && name.ends_with(".tmp"))
        }));
    }

    #[cfg(unix)]
    #[test]
    fn session_store_permissions_are_restricted_before_reading() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("session.json");
        fs::write(
            &path,
            serde_json::to_vec(&SessionTokens {
                access_token: "credential".to_string(),
                ..SessionTokens::default()
            })
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut config = config();
        config.token_file = path.to_string_lossy().to_string();

        let loaded = ConfiguredRemoteClient::new(config).load_tokens().unwrap();

        assert_eq!(loaded.access_token, "credential");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn mock_server_proves_refresh_then_reboot_request_construction() {
        let server = spawn_mock_server(vec![
            MockResponse {
                status: Some(200),
                body: r#"{"access_token":"access-new","refresh_token":"refresh-new","expires_at":4102444800}"#.to_string(),
                headers: Vec::new(),
            },
            MockResponse {
                status: Some(202),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
        ]);
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                access_token: "access-old".to_string(),
                refresh_token: Some("refresh-old".to_string()),
                expires_at: Some(1),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.refresh = Some(request_template(
            format!("http://{}/refresh", server.address),
            serde_json::json!({"refresh_token":"${refresh_token}"}),
            vec![200],
        ));
        config.remote.reboot = Some(request_template(
            format!("http://{}/reboot", server.address),
            serde_json::json!({"access":"${access_token}"}),
            vec![202],
        ));

        let mut client = ConfiguredRemoteClient::new(config);
        assert_eq!(
            client.reboot().unwrap(),
            RemoteCallOutcome::Accepted { status: 202 }
        );
        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("refresh-old"));
        assert!(requests[1].contains("Bearer access-new"));
        assert!(requests[1].contains("access-new"));
        let stored: SessionTokens = serde_json::from_slice(&fs::read(token_file).unwrap()).unwrap();
        assert_eq!(stored.access_token, "access-new");
        assert_eq!(stored.refresh_token.as_deref(), Some("refresh-new"));
    }

    #[test]
    fn mock_server_captures_xiaomi_signed_reboot_request() {
        let server = spawn_mock_server(vec![
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
        ]);
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("xiaomi-session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                access_token: String::new(),
                service_token: Some("service-secret".to_string()),
                ssecurity: Some(BASE64.encode([7_u8; 32])),
                expires_at: Some(4_102_444_800),
                user_id: Some("user-1".to_string()),
                c_user_id: Some("c-user-1".to_string()),
                pass_token: Some("pass-secret".to_string()),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();

        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.xiaomi = Some(XiaomiRemoteConfig {
            base_url: format!("http://{}", server.address),
            account_base_url: format!("http://{}", server.address),
            router_private_id: Some("router-private-123".to_string()),
            user_agent: "Mi WiFi/5.9.0".to_string(),
            success_statuses: vec![200],
        });

        let mut client = ConfiguredRemoteClient::new(config);
        assert_eq!(
            client.reboot().unwrap(),
            RemoteCallOutcome::Accepted { status: 200 }
        );
        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        let preflight = &requests[0];
        assert!(preflight.starts_with("GET /r/api/xqsystem/init_info?"));
        assert!(preflight.contains("serviceToken=service-secret"));
        assert!(preflight.contains("userId=user-1"));
        assert!(preflight.contains("cUserId=c-user-1"));
        assert!(preflight.contains("passToken=pass-secret"));
        assert!(preflight.contains("MiWiFi-Supported-Compression: deflate"));
        assert!(preflight.contains("deviceID="));
        assert!(preflight.contains("deviceId="));
        assert!(preflight.contains("routerID="));
        assert!(preflight.contains("rc4_hash__="));
        assert!(preflight.contains("signature="));
        assert!(preflight.contains("_nonce="));

        let request = &requests[1];
        assert!(request.starts_with("POST /s/diagnosis/control/reboot HTTP/1.1"));
        assert!(request.contains("serviceToken=service-secret"));
        assert!(request.contains("userId=user-1"));
        assert!(request.contains("cUserId=c-user-1"));
        assert!(request.contains("passToken=pass-secret"));
        assert!(request.contains("MiWiFi-Supported-Compression: deflate"));
        assert!(request.contains("Content-Type: application/x-www-form-urlencoded"));
        assert!(request.contains("deviceID="));
        assert!(request.contains("deviceId="));
        assert!(request.contains("routerID="));
        assert!(request.contains("rc4_hash__="));
        assert!(request.contains("signature="));
        assert!(request.contains("_nonce="));
    }

    #[test]
    fn xiaomi_direct_pass_token_refresh_precedes_reboot() {
        let server = spawn_mock_server(vec![
            MockResponse {
                status: Some(200),
                body: format!(
                    "&&&START&&&{{\"code\":0,\"ssecurity\":\"{}\",\"nonce\":123456,\"location\":\"http://{}/pass/serviceLoginAuth2?foo=bar\"}}",
                    BASE64.encode([8_u8; 32]),
                    "{address}"
                ),
                headers: Vec::new(),
            },
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: vec![(
                    "Set-Cookie".to_string(),
                    "serviceToken=service-new; Path=/; HttpOnly".to_string(),
                )],
            },
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
        ]);
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("xiaomi-session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                service_token: Some("service-old".to_string()),
                ssecurity: Some(BASE64.encode([7_u8; 32])),
                expires_at: Some(1),
                user_id: Some("user-1".to_string()),
                pass_token: Some("pass-secret".to_string()),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();

        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.xiaomi = Some(XiaomiRemoteConfig {
            base_url: format!("http://{}", server.address),
            account_base_url: format!("http://{}", server.address),
            router_private_id: Some("router-private-123".to_string()),
            user_agent: "Android APP/com.xiaomi.router APPV/5.9.0".to_string(),
            success_statuses: vec![200],
        });

        let mut client = ConfiguredRemoteClient::new(config);
        assert_eq!(
            client.reboot().unwrap(),
            RemoteCallOutcome::Accepted { status: 200 }
        );

        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with("GET /pass/serviceLogin?sid=xiaoqiang&_json=true HTTP/1.1"));
        assert!(requests[0].contains("Cookie: passToken=pass-secret; userId=user-1"));
        assert!(requests[1].starts_with("GET /pass/serviceLoginAuth2?foo=bar&clientSign="));
        assert!(requests[1].contains("_userIdNeedEncrypt=true"));
        assert!(requests[2].starts_with("GET /r/api/xqsystem/init_info?"));
        assert!(requests[2].contains("serviceToken=service-new"));
        assert!(requests[2].contains("userId=user-1"));
        assert!(requests[2].contains("passToken=pass-secret"));
        assert!(requests[3].starts_with("POST /s/diagnosis/control/reboot HTTP/1.1"));
        assert!(requests[3].contains("serviceToken=service-new"));
        assert!(requests[3].contains("userId=user-1"));
        assert!(requests[3].contains("passToken=pass-secret"));

        let stored: SessionTokens = serde_json::from_slice(&fs::read(token_file).unwrap()).unwrap();
        assert_eq!(stored.service_token.as_deref(), Some("service-new"));
        assert_eq!(
            stored.ssecurity.as_deref().unwrap(),
            BASE64.encode([8_u8; 32])
        );
        assert!(stored.expires_at.unwrap_or_default() > Utc::now().timestamp());
    }

    #[test]
    fn authenticated_preflight_401_prefers_direct_refresh_before_emulator_collection() {
        let server = spawn_mock_server(vec![
            MockResponse {
                status: Some(401),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
            MockResponse {
                status: Some(200),
                body: format!(
                    "&&&START&&&{{\"code\":0,\"ssecurity\":\"{}\",\"nonce\":123456,\"location\":\"http://{}/pass/serviceLoginAuth2\"}}",
                    BASE64.encode([8_u8; 32]),
                    "{address}"
                ),
                headers: Vec::new(),
            },
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: vec![(
                    "Set-Cookie".to_string(),
                    "serviceToken=service-new; Path=/; HttpOnly".to_string(),
                )],
            },
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
            MockResponse {
                status: Some(200),
                body: "{}".to_string(),
                headers: Vec::new(),
            },
        ]);
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("xiaomi-session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                service_token: Some("service-old".to_string()),
                ssecurity: Some(BASE64.encode([7_u8; 32])),
                expires_at: Some(Utc::now().timestamp() + 86_400),
                user_id: Some("user-1".to_string()),
                pass_token: Some("pass-secret".to_string()),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();

        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.xiaomi = Some(XiaomiRemoteConfig {
            base_url: format!("http://{}", server.address),
            account_base_url: format!("http://{}", server.address),
            router_private_id: Some("router-private-123".to_string()),
            user_agent: "Android APP/com.xiaomi.router APPV/5.9.0".to_string(),
            success_statuses: vec![200],
        });
        let context = crate::modules::module_context(
            "miwatch",
            dir.path().to_path_buf(),
            dir.path().to_path_buf(),
            dir.path().join("logs"),
        );

        let mut client = ConfiguredRemoteClient::with_context(config, &context);
        assert_eq!(
            client.reboot().unwrap(),
            RemoteCallOutcome::Accepted { status: 200 }
        );

        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].starts_with("GET /r/api/xqsystem/init_info?"));
        assert!(requests[1].starts_with("GET /pass/serviceLogin?"));
        assert!(requests[2].starts_with("GET /pass/serviceLoginAuth2?"));
        assert!(requests[3].starts_with("GET /r/api/xqsystem/init_info?"));
        assert!(requests[4].starts_with("POST /s/diagnosis/control/reboot"));
    }

    #[test]
    fn mock_server_rate_limit_is_rejected_without_retry() {
        let server = spawn_mock_server(vec![MockResponse {
            status: Some(429),
            body: "{}".to_string(),
            headers: Vec::new(),
        }]);
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                access_token: "access".to_string(),
                refresh_token: None,
                expires_at: None,
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.reboot = Some(request_template(
            format!("http://{}/reboot", server.address),
            serde_json::json!({}),
            vec![202],
        ));
        let mut client = ConfiguredRemoteClient::new(config);
        assert_eq!(
            client.reboot().unwrap(),
            RemoteCallOutcome::Rejected { status: 429 }
        );
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn accepted_request_connection_loss_is_ambiguous() {
        let server = spawn_mock_server(vec![MockResponse {
            status: None,
            body: String::new(),
            headers: Vec::new(),
        }]);
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                access_token: "access".to_string(),
                refresh_token: None,
                expires_at: None,
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.reboot = Some(request_template(
            format!("http://{}/reboot", server.address),
            serde_json::json!({}),
            vec![202],
        ));
        let mut client = ConfiguredRemoteClient::new(config);
        assert!(matches!(
            client.reboot().unwrap(),
            RemoteCallOutcome::Ambiguous { .. }
        ));
    }

    #[test]
    fn unavailable_api_path_is_ambiguous_and_not_retried_by_client() {
        let dir = tempdir().unwrap();
        let token_file = dir.path().join("session.json");
        fs::write(
            &token_file,
            serde_json::to_vec(&SessionTokens {
                access_token: "access".to_string(),
                refresh_token: None,
                expires_at: None,
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let mut config = config();
        config.verified_remote_api = true;
        config.token_file = token_file.to_string_lossy().to_string();
        config.remote.reboot = Some(request_template(
            "http://127.0.0.1:1/reboot".to_string(),
            serde_json::json!({}),
            vec![202],
        ));
        let mut client = ConfiguredRemoteClient::new(config);
        assert!(matches!(
            client.reboot().unwrap(),
            RemoteCallOutcome::Ambiguous { .. }
        ));
    }
}
