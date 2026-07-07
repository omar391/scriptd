#![allow(dead_code)]

use chrono::{
    DateTime, Datelike, Duration, Local, NaiveDateTime, NaiveTime, TimeZone, Timelike, Weekday,
};
use cron::Schedule;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use crate::paths::{
    expand_home, resolve_service_config_path, resolve_state_dir, resolve_state_file,
};
use anyhow::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub label: String,
    #[serde(rename = "log_dir")]
    pub log_dir: String,
    #[serde(default)]
    pub watch: bool,
    #[serde(default = "default_self_update_check_hours")]
    pub self_update_check_hours: u64,
    #[serde(default)]
    pub modules: HashMap<String, ServiceModuleConfig>,

    #[serde(skip)]
    pub path: PathBuf,
    #[serde(skip)]
    pub root_dir: PathBuf,
    #[serde(skip)]
    pub state_dir: PathBuf,
    #[serde(skip)]
    pub state_file: PathBuf,
}

impl ServiceConfig {
    pub fn expanded_log_dir(&self) -> PathBuf {
        expand_home(&self.log_dir)
    }

    pub fn self_update_check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.self_update_check_hours.saturating_mul(60 * 60))
    }
}

fn default_self_update_check_hours() -> u64 {
    12
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceModuleConfig {
    pub enabled: bool,
    #[serde(default)]
    pub schedule: Option<ModuleSchedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WeekdayName {
    Sun,
    #[default]
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
}

impl WeekdayName {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "sun" => Some(Self::Sun),
            "mon" => Some(Self::Mon),
            "tue" => Some(Self::Tue),
            "wed" => Some(Self::Wed),
            "thu" | "thur" | "thurs" => Some(Self::Thu),
            "fri" => Some(Self::Fri),
            "sat" => Some(Self::Sat),
            _ => None,
        }
    }

    fn as_chrono(&self) -> Weekday {
        match self {
            Self::Sun => Weekday::Sun,
            Self::Mon => Weekday::Mon,
            Self::Tue => Weekday::Tue,
            Self::Wed => Weekday::Wed,
            Self::Thu => Weekday::Thu,
            Self::Fri => Weekday::Fri,
            Self::Sat => Weekday::Sat,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ScheduleWindow {
    pub start: String,
    pub end: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ModuleSchedule {
    #[serde(default)]
    pub cron: Option<Vec<String>>,
    #[serde(rename = "every_seconds", default)]
    pub every_seconds: Option<u64>,
    #[serde(rename = "every_minutes", default)]
    pub every_minutes: Option<u64>,
    #[serde(rename = "every_hours", default)]
    pub every_hours: Option<u64>,
    #[serde(rename = "daily_at", default)]
    pub daily_at: Option<Vec<String>>,
    #[serde(default)]
    pub weekdays: Option<Vec<WeekdayName>>,
    #[serde(default)]
    pub window: Option<ScheduleWindow>,
}

impl ModuleSchedule {
    pub fn interval_seconds(&self) -> Option<u64> {
        self.every_seconds
            .or_else(|| self.every_minutes.map(|minutes| minutes.saturating_mul(60)))
            .or_else(|| self.every_hours.map(|hours| hours.saturating_mul(60 * 60)))
    }

    pub fn exactly_one_trigger(&self) -> bool {
        let enabled = [
            self.cron.is_some(),
            self.every_seconds.is_some(),
            self.every_minutes.is_some(),
            self.every_hours.is_some(),
            self.daily_at.is_some(),
        ];
        enabled.into_iter().filter(|value| *value).count() == 1
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.exactly_one_trigger() {
            anyhow::bail!(
                "module schedule must define exactly one trigger among cron/every_seconds/every_minutes/every_hours/daily_at"
            );
        }

        if let Some(window) = &self.window {
            parse_time(&window.start)?;
            parse_time(&window.end)?;
        }

        if let Some(values) = &self.daily_at {
            for value in values {
                parse_time(value)?;
            }
        }

        if let Some(values) = &self.cron {
            if values.is_empty() {
                anyhow::bail!("cron schedule must not be empty");
            }
            for expression in values {
                parse_cron_expression(expression)?;
            }
        }

        Ok(())
    }

    pub fn allow_now(&self, now: &DateTime<Local>) -> bool {
        if let Some(weekdays) = &self.weekdays {
            if !weekdays
                .iter()
                .any(|value| value.as_chrono() == now.weekday())
            {
                return false;
            }
        }

        if let Some(window) = &self.window {
            return within_window_raw(window, now);
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct ParsedModule {
    pub manifest: ModuleManifest,
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifest {
    pub id: String,
    #[serde(rename = "display_name")]
    pub display_name: Option<String>,
    pub mode: String,
    #[serde(rename = "interval_seconds")]
    pub interval_seconds: Option<u64>,
}

impl ModuleManifest {
    pub fn interval_ms(&self) -> Option<u64> {
        self.interval_seconds
            .and_then(|value| value.checked_mul(1000))
    }
}

#[derive(Debug)]
pub struct ModuleReloadDiff {
    pub to_start: Vec<String>,
    pub to_stop: Vec<String>,
}

#[derive(Debug)]
pub struct IntervalPlan {
    pub should_schedule: bool,
    pub delay_ms: Option<u64>,
    pub next_run_at: Option<DateTime<Local>>,
}

#[derive(Debug, Clone)]
pub struct ReadableInterval {
    pub schedule: String,
}

impl Display for ReadableInterval {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.schedule)
    }
}

fn parse_cron_expression(raw: &str) -> anyhow::Result<Schedule> {
    raw.parse::<Schedule>()
        .map_err(|error| anyhow::anyhow!("invalid cron {raw}: {error}"))
}

fn parse_time(raw: &str) -> anyhow::Result<NaiveTime> {
    NaiveTime::parse_from_str(raw, "%H:%M")
        .map_err(|error| anyhow::anyhow!("invalid time value {raw}: {error}"))
}

fn within_window_raw(window: &ScheduleWindow, now: &DateTime<Local>) -> bool {
    let (start, end) = match (parse_time(&window.start), parse_time(&window.end)) {
        (Ok(start), Ok(end)) => (start, end),
        _ => return false,
    };

    let now_seconds = now.time().num_seconds_from_midnight();
    let start_seconds = start.num_seconds_from_midnight();
    let end_seconds = end.num_seconds_from_midnight();

    if start_seconds <= end_seconds {
        now_seconds >= start_seconds && now_seconds <= end_seconds
    } else {
        now_seconds >= start_seconds || now_seconds <= end_seconds
    }
}

fn next_interval_candidates(
    interval_seconds: u64,
    now: DateTime<Local>,
) -> Option<DateTime<Local>> {
    now.checked_add_signed(Duration::seconds(
        i64::try_from(interval_seconds).unwrap_or(0),
    ))
}

fn next_interval_candidate_in_window(
    interval_seconds: u64,
    schedule: &ModuleSchedule,
    now: DateTime<Local>,
) -> Option<DateTime<Local>> {
    let mut candidate = next_interval_candidates(interval_seconds, now)?;
    if schedule.window.is_some() {
        return next_time_in_window(schedule, candidate);
    }

    let max_checks = 14u64.saturating_mul(24 * 60 * 60) / interval_seconds.max(1) + 1;

    for _ in 0..max_checks {
        if schedule.allow_now(&candidate) {
            return Some(candidate);
        }

        candidate = next_interval_candidates(interval_seconds, candidate)?;
    }

    None
}

fn local_datetime_on(date: chrono::NaiveDate, time: NaiveTime) -> Option<DateTime<Local>> {
    let raw = date.and_time(time);
    Local
        .from_local_datetime(&raw)
        .earliest()
        .or_else(|| Local.from_local_datetime(&raw).single())
}

fn next_time_in_window(
    schedule: &ModuleSchedule,
    earliest: DateTime<Local>,
) -> Option<DateTime<Local>> {
    let window = schedule.window.as_ref()?;
    let start = parse_time(&window.start).ok()?;
    let end = parse_time(&window.end).ok()?;
    let overnight = start.num_seconds_from_midnight() > end.num_seconds_from_midnight();
    let mut best: Option<DateTime<Local>> = None;

    for day_offset in -1..=14 {
        let Some(window_date) = earliest
            .date_naive()
            .checked_add_signed(Duration::days(day_offset))
        else {
            continue;
        };
        let Some(window_start) = local_datetime_on(window_date, start) else {
            continue;
        };
        let window_end_date = if overnight {
            window_date
                .checked_add_days(chrono::Days::new(1))
                .unwrap_or(window_date)
        } else {
            window_date
        };
        let Some(window_end) = local_datetime_on(window_end_date, end) else {
            continue;
        };

        if window_end < earliest {
            continue;
        }

        let candidate = if window_start < earliest {
            earliest
        } else {
            window_start
        };
        if candidate <= window_end
            && schedule.allow_now(&candidate)
            && best.is_none_or(|current| candidate < current)
        {
            best = Some(candidate);
        }
    }

    best
}

fn next_daily_candidates(
    times: &[String],
    schedule: &ModuleSchedule,
    now: DateTime<Local>,
) -> Option<DateTime<Local>> {
    let mut best: Option<DateTime<Local>> = None;

    for day_offset in 0..14i64 {
        let candidate_day = now
            .date_naive()
            .checked_add_days(chrono::Days::new(u64::try_from(day_offset).unwrap_or(0)))
            .unwrap_or_else(|| now.date_naive());

        for raw in times {
            let Ok(parsed) = parse_time(raw) else {
                continue;
            };

            let day_start: NaiveDateTime = candidate_day.and_time(parsed);
            let candidate = now
                .timezone()
                .from_local_datetime(&day_start)
                .earliest()
                .or_else(|| now.timezone().from_local_datetime(&day_start).single());
            let Some(candidate) = candidate else {
                continue;
            };

            if candidate <= now && day_offset == 0 {
                continue;
            }

            if let Some(allowed) = &schedule.weekdays {
                if !allowed
                    .iter()
                    .any(|weekday| weekday.as_chrono() == candidate.weekday())
                {
                    continue;
                }
            }

            if let Some(window) = &schedule.window {
                if !within_window_raw(window, &candidate) {
                    continue;
                }
            }

            if best.is_none_or(|current| candidate < current) {
                best = Some(candidate);
            }
        }
    }

    best
}

fn next_cron_candidates(expressions: &[String], now: DateTime<Local>) -> Option<DateTime<Local>> {
    let mut best: Option<DateTime<Local>> = None;

    for expression in expressions {
        let Ok(schedule) = parse_cron_expression(expression) else {
            continue;
        };

        if let Some(candidate) = schedule.after(&now).next() {
            if best.is_none_or(|current| candidate < current) {
                best = Some(candidate);
            }
        }
    }

    best
}

pub fn read_service_config(root: &Path) -> anyhow::Result<ServiceConfig> {
    let path = resolve_service_config_path(root);
    let text = fs::read_to_string(&path)?;
    let mut config: ServiceConfig = serde_yaml::from_str(&text)?;
    config.path = path;
    config.root_dir = root.to_path_buf();
    config.state_dir = resolve_state_dir();
    config.state_file = resolve_state_file();
    for (module_id, module) in config.modules.iter() {
        if let Some(schedule) = &module.schedule {
            schedule
                .validate()
                .with_context(|| format!("invalid schedule for module {module_id}"))?;
        }
    }
    if config.self_update_check_hours == 0 {
        anyhow::bail!("service self_update_check_hours must be greater than zero");
    }
    Ok(config)
}

pub fn read_module_manifest(id: &str, root: &Path) -> anyhow::Result<ParsedModule> {
    let manifest_path = root.join("modules").join(id).join("module.yaml");
    let raw = fs::read_to_string(&manifest_path)?;
    let manifest: ModuleManifest = serde_yaml::from_str(&raw)?;
    if manifest.id != id {
        anyhow::bail!("module manifest id mismatch: {} != {}", manifest.id, id);
    }

    Ok(ParsedModule {
        manifest,
        dir: manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.join("modules").join(id)),
    })
}

pub fn next_scheduled_run(
    schedule: &Option<ModuleSchedule>,
    now: DateTime<Local>,
) -> Option<DateTime<Local>> {
    let schedule = schedule.as_ref()?;

    let candidate = if let Some(every) = schedule.interval_seconds() {
        if schedule.window.is_some() || schedule.weekdays.is_some() {
            next_interval_candidate_in_window(every, schedule, now)
        } else {
            next_interval_candidates(every, now)
        }
    } else if let Some(times) = &schedule.daily_at {
        next_daily_candidates(times, schedule, now)
    } else if let Some(expressions) = &schedule.cron {
        next_cron_candidates(expressions, now)
    } else {
        None
    };

    candidate.and_then(|value| schedule.allow_now(&value).then_some(value))
}

pub fn find_next_in_window(
    schedule: &ModuleSchedule,
    now: DateTime<Local>,
    max_days: i64,
) -> Option<DateTime<Local>> {
    for day_offset in 1..=max_days {
        let day = now
            .date_naive()
            .checked_add_days(chrono::Days::new(u64::try_from(day_offset).unwrap_or(0)))
            .unwrap_or_else(|| now.date_naive());
        if let Some(times) = &schedule.daily_at {
            for raw in times {
                let parsed = match parse_time(raw) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let dt = now
                    .timezone()
                    .from_local_datetime(&day.and_time(parsed))
                    .earliest()
                    .or_else(|| {
                        now.timezone()
                            .from_local_datetime(&day.and_time(parsed))
                            .single()
                    });
                if let Some(candidate) = dt {
                    if schedule.allow_now(&candidate) {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

pub fn build_interval_plan(
    desired_enabled: bool,
    is_running: bool,
    schedule: &Option<ModuleSchedule>,
    now: DateTime<Local>,
) -> IntervalPlan {
    if !desired_enabled || is_running {
        return IntervalPlan {
            should_schedule: false,
            delay_ms: None,
            next_run_at: None,
        };
    }

    let Some(next) = next_scheduled_run(schedule, now) else {
        return IntervalPlan {
            should_schedule: false,
            delay_ms: None,
            next_run_at: None,
        };
    };

    let delay = next
        .signed_duration_since(now)
        .to_std()
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0);
    IntervalPlan {
        should_schedule: true,
        delay_ms: Some(delay),
        next_run_at: Some(next),
    }
}

pub fn compare_enabled(
    previous: &HashMap<String, ServiceModuleConfig>,
    next: &HashMap<String, ServiceModuleConfig>,
) -> ModuleReloadDiff {
    let previous_keys: BTreeSet<&String> = previous.keys().collect();
    let next_keys: BTreeSet<&String> = next.keys().collect();

    let to_start = next_keys
        .into_iter()
        .filter_map(|module| {
            if previous
                .get(module)
                .map(|entry| entry.enabled)
                .unwrap_or(false)
            {
                None
            } else if next.get(module).map(|entry| entry.enabled).unwrap_or(false) {
                Some((*module).to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let to_stop = previous_keys
        .into_iter()
        .filter_map(|module| {
            if previous
                .get(module)
                .map(|entry| entry.enabled)
                .unwrap_or(false)
                && !next.get(module).map(|entry| entry.enabled).unwrap_or(false)
            {
                Some((*module).to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    ModuleReloadDiff {
        to_start: {
            let mut next = to_start;
            next.sort_unstable();
            next
        },
        to_stop: {
            let mut stop = to_stop;
            stop.sort_unstable();
            stop
        },
    }
}

#[cfg(test)]
fn assert_weekday_name(raw: &str) {
    let parsed = WeekdayName::parse(raw);
    assert!(parsed.is_some(), "expected weekday {raw} to parse");
}

pub fn build_state_freshness_reason(
    state: &crate::status::PersistedState,
    launchd_loaded: bool,
    launchd_pid: Option<u32>,
    config: &ServiceConfig,
) -> Option<String> {
    if state.label != config.label {
        return Some("label mismatch".into());
    }

    if state.root_dir != config.root_dir.to_string_lossy() {
        return Some("state file belongs to another repo root".into());
    }

    if state.config_path != config.path.to_string_lossy() {
        return Some("state file belongs to another config path".into());
    }

    if !launchd_loaded {
        return Some("LaunchAgent not loaded".into());
    }

    if let Some(loaded_pid) = launchd_pid {
        if loaded_pid != u32::try_from(state.supervisor.pid).ok().unwrap_or_default() {
            return Some("supervisor PID does not match launchd PID".into());
        }
    }

    None
}

pub fn update_service_module_config(
    root: &Path,
    module: &str,
    patch: ServiceModuleConfig,
) -> anyhow::Result<()> {
    let mut config = read_service_config(root)?;
    let entry = config.modules.entry(module.to_string()).or_default();
    entry.enabled = patch.enabled;
    if let Some(schedule) = patch.schedule {
        entry.schedule = Some(schedule);
    }

    if let Some(schedule) = &entry.schedule {
        schedule.validate()?;
    }

    let output = serde_yaml::to_string(&config)?;
    fs::write(config.path, output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[test]
    fn parses_service_config_and_expands_home_dir() {
        let temp = tempdir().expect("temp dir");
        let repo = temp.path();
        let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
        let service_yaml = "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nself_update_check_hours: 12\nmodules:\n  mbrew:\n    enabled: true\n    schedule:\n      every_hours: 12\n";
        fs::write(repo.join("service.yaml"), service_yaml).expect("write service config");

        let config = read_service_config(repo).expect("read config");
        assert_eq!(config.label, "com.omar.scriptd");
        assert!(config.watch);
        assert_eq!(config.self_update_check_hours, 12);
        assert_eq!(config.log_dir, "~/Library/Logs/scriptd");
        assert_eq!(
            config.expanded_log_dir().to_string_lossy(),
            format!("{}/Library/Logs/scriptd", home.to_string_lossy())
        );
        assert!(config.modules.get("mbrew").expect("module").enabled);
        assert_eq!(
            config
                .modules
                .get("mbrew")
                .expect("module")
                .schedule
                .as_ref()
                .and_then(|schedule| schedule.every_hours),
            Some(12)
        );
    }

    #[test]
    fn read_module_manifest_rejects_id_mismatch() {
        let temp = tempdir().expect("temp dir");
        let module_dir = temp.path().join("modules").join("mwifi");
        std::fs::create_dir_all(&module_dir).expect("create module dir");
        std::fs::write(
            module_dir.join("module.yaml"),
            "id: wrong-id\nmode: interval\ninterval_seconds: 30\n",
        )
        .expect("write manifest");

        let result = read_module_manifest("mwifi", temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn read_service_config_rejects_invalid_schedule() {
        let temp = tempdir().expect("temp dir");
        let service_yaml = "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nself_update_check_hours: 12\nmodules:\n  mbrew:\n    enabled: true\n    schedule:\n      every_hours: 12\n      daily_at:\n        - \"09:00\"\n";
        fs::write(temp.path().join("service.yaml"), service_yaml).expect("write service config");

        let error = read_service_config(temp.path()).expect_err("invalid schedule should fail");
        assert!(error
            .to_string()
            .contains("invalid schedule for module mbrew"));
    }

    #[test]
    fn validate_daily_and_cron_exclusive() {
        let schedule = ModuleSchedule {
            every_minutes: Some(2),
            daily_at: Some(vec!["09:00".to_string()]),
            ..ModuleSchedule::default()
        };
        assert!(schedule.validate().is_err());

        let schedule = ModuleSchedule {
            cron: Some(vec!["0 */5 * * * * *".to_string()]),
            ..ModuleSchedule::default()
        };
        assert!(schedule.validate().is_ok());
    }

    #[test]
    fn next_schedule_respects_window() {
        let schedule = ModuleSchedule {
            daily_at: Some(vec!["10:00".to_string()]),
            window: Some(ScheduleWindow {
                start: "07:00".to_string(),
                end: "18:00".to_string(),
            }),
            ..ModuleSchedule::default()
        };

        let now = Local
            .with_ymd_and_hms(2026, 6, 2, 8, 30, 0)
            .single()
            .expect("valid datetime");
        let next = next_scheduled_run(&Some(schedule), now);
        assert!(next.is_some());
    }

    #[test]
    fn compare_enable_flags() {
        let mut previous = HashMap::new();
        previous.insert(
            "mbrew".to_string(),
            ServiceModuleConfig {
                enabled: true,
                schedule: None,
            },
        );
        previous.insert(
            "mcpu".to_string(),
            ServiceModuleConfig {
                enabled: false,
                schedule: None,
            },
        );

        let mut next = HashMap::new();
        next.insert(
            "mbrew".to_string(),
            ServiceModuleConfig {
                enabled: false,
                schedule: None,
            },
        );
        next.insert(
            "mcpu".to_string(),
            ServiceModuleConfig {
                enabled: true,
                schedule: None,
            },
        );

        let diff = compare_enabled(&previous, &next);
        assert_eq!(diff.to_start, vec!["mcpu".to_string()]);
        assert_eq!(diff.to_stop, vec!["mbrew".to_string()]);
    }

    #[test]
    fn build_interval_plan_blocks_running_jobs() {
        let schedule = ModuleSchedule {
            every_seconds: Some(30),
            ..ModuleSchedule::default()
        };
        let now = Local::now();
        let blocked = build_interval_plan(true, true, &Some(schedule.clone()), now);
        assert!(!blocked.should_schedule);
        assert_eq!(blocked.delay_ms, None);

        let blocked = build_interval_plan(false, false, &Some(schedule), now);
        assert!(!blocked.should_schedule);
        assert_eq!(blocked.delay_ms, None);
    }

    #[test]
    fn build_interval_plan_for_disabled_schedule_starts_near_future() {
        let schedule = ModuleSchedule {
            every_seconds: Some(30),
            ..ModuleSchedule::default()
        };
        let now = Local
            .with_ymd_and_hms(2026, 6, 2, 10, 0, 0)
            .single()
            .expect("valid datetime");
        let plan = build_interval_plan(true, false, &Some(schedule), now);
        assert!(plan.should_schedule);
        assert_eq!(plan.delay_ms, Some(30_000));
    }

    #[test]
    fn next_scheduled_run_rejects_windows_when_out_of_window() {
        let schedule = ModuleSchedule {
            daily_at: Some(vec!["08:00".to_string()]),
            window: Some(ScheduleWindow {
                start: "09:00".to_string(),
                end: "10:00".to_string(),
            }),
            ..ModuleSchedule::default()
        };

        let now = Local
            .with_ymd_and_hms(2026, 6, 2, 8, 30, 0)
            .single()
            .expect("valid datetime");
        assert!(next_scheduled_run(&Some(schedule), now).is_none());
    }

    #[test]
    fn next_scheduled_run_for_interval_schedule_clamps_past_window_edge() {
        let schedule = ModuleSchedule {
            every_minutes: Some(5),
            window: Some(ScheduleWindow {
                start: "00:00".to_string(),
                end: "06:00".to_string(),
            }),
            ..ModuleSchedule::default()
        };

        let now = Local
            .with_ymd_and_hms(2026, 6, 2, 5, 58, 0)
            .single()
            .expect("valid datetime");
        let next = next_scheduled_run(&Some(schedule), now).expect("next schedule");

        assert_eq!(
            next.date_naive(),
            now.date_naive().succ_opt().expect("next day")
        );
        assert_eq!(next.hour(), 0);
        assert_eq!(next.minute(), 0);
    }

    #[test]
    fn next_scheduled_run_for_interval_schedule_clamps_to_next_window() {
        let schedule = ModuleSchedule {
            every_hours: Some(12),
            window: Some(ScheduleWindow {
                start: "06:00".to_string(),
                end: "08:00".to_string(),
            }),
            ..ModuleSchedule::default()
        };

        let now = Local
            .with_ymd_and_hms(2026, 6, 8, 13, 50, 0)
            .single()
            .expect("valid datetime");
        let next = next_scheduled_run(&Some(schedule), now).expect("next schedule");

        assert_eq!(
            next.date_naive(),
            now.date_naive().succ_opt().expect("next day")
        );
        assert_eq!(next.hour(), 6);
        assert_eq!(next.minute(), 0);
    }

    #[test]
    fn next_scheduled_run_for_interval_schedule_keeps_due_time_inside_window() {
        let schedule = ModuleSchedule {
            every_minutes: Some(30),
            window: Some(ScheduleWindow {
                start: "06:00".to_string(),
                end: "08:00".to_string(),
            }),
            ..ModuleSchedule::default()
        };

        let now = Local
            .with_ymd_and_hms(2026, 6, 8, 6, 15, 0)
            .single()
            .expect("valid datetime");
        let next = next_scheduled_run(&Some(schedule), now).expect("next schedule");

        assert_eq!(next.date_naive(), now.date_naive());
        assert_eq!(next.hour(), 6);
        assert_eq!(next.minute(), 45);
    }

    #[test]
    fn next_scheduled_run_returns_next_weekday_match_for_daily_and_weekdays() {
        let schedule = ModuleSchedule {
            daily_at: Some(vec!["09:00".to_string()]),
            weekdays: Some(vec![WeekdayName::Mon, WeekdayName::Wed]),
            ..ModuleSchedule::default()
        };

        let now = Local
            .with_ymd_and_hms(2026, 6, 2, 10, 30, 0)
            .single()
            .expect("valid datetime");
        let next = next_scheduled_run(&Some(schedule), now).expect("next schedule");
        assert_eq!(next.weekday(), Weekday::Wed);
        assert_eq!(next.hour(), 9);
        assert_eq!(next.minute(), 0);
    }

    #[test]
    fn parses_weekday_names_from_config_input() {
        for name in ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] {
            assert_weekday_name(name);
        }
    }

    #[test]
    fn next_scheduled_run_prefers_cron_expression_next_matching_second() {
        let schedule = ModuleSchedule {
            cron: Some(vec!["0 0 */2 * * *".to_string()]),
            ..ModuleSchedule::default()
        };

        let now = Local
            .with_ymd_and_hms(2026, 6, 2, 10, 0, 30)
            .single()
            .expect("valid datetime");
        let next = next_scheduled_run(&Some(schedule), now).expect("next scheduled run");

        assert_eq!(next.hour(), 12);
        assert_eq!(next.minute(), 0);
        assert_eq!(next.second(), 0);
    }

    #[test]
    fn next_scheduled_run_rejects_invalid_cron_expression() {
        let schedule = ModuleSchedule {
            cron: Some(vec!["nonsense".to_string()]),
            ..ModuleSchedule::default()
        };
        assert!(next_scheduled_run(&Some(schedule), Local::now()).is_none());
    }

    #[test]
    fn state_freshness_marks_stale_when_launchd_not_loaded() {
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: Local::now().to_rfc3339(),
            supervisor: crate::status::PersistedSupervisorState {
                pid: 100,
                started_at: Local::now().to_rfc3339(),
                watch: true,
            },
            modules: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };
        let reason = build_state_freshness_reason(&state, false, None, &config)
            .expect("expected stale reason");
        assert!(reason.contains("LaunchAgent not loaded"));
    }

    #[test]
    fn state_freshness_marks_stale_if_launchd_pid_mismatch() {
        let updated = Local::now().to_rfc3339();
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: updated,
            supervisor: crate::status::PersistedSupervisorState {
                pid: 100,
                started_at: Local::now().to_rfc3339(),
                watch: true,
            },
            modules: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };

        let reason = build_state_freshness_reason(&state, true, Some(777), &config)
            .expect("expected pid mismatch reason");
        assert!(reason.contains("PID"));
    }

    #[test]
    fn state_freshness_reports_current_when_live() {
        let now = Local::now().to_rfc3339();
        let pid = 123i32;
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: now.clone(),
            supervisor: crate::status::PersistedSupervisorState {
                pid,
                started_at: now.clone(),
                watch: true,
            },
            modules: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };

        let reason = build_state_freshness_reason(&state, true, Some(pid as u32), &config);
        assert!(reason.is_none());
    }

    #[test]
    fn state_freshness_allows_old_quiet_state_when_launchd_live() {
        let pid = 321i32;
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: "2020-01-01T00:00:00Z".to_string(),
            supervisor: crate::status::PersistedSupervisorState {
                pid,
                started_at: "2020-01-01T00:00:00Z".to_string(),
                watch: true,
            },
            modules: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };

        let reason = build_state_freshness_reason(&state, true, Some(pid as u32), &config);
        assert!(reason.is_none());
    }
}
