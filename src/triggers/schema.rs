use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, LocalResult, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerConfig {
    pub enabled: bool,
    pub module: String,
    pub fire: FirePolicy,
    pub when: Condition,
}

impl TriggerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.module.trim().is_empty() {
            anyhow::bail!("trigger module must not be empty");
        }
        self.when.validate().context("invalid trigger condition")?;
        self.fire.validate().context("invalid trigger fire policy")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum FirePolicy {
    EveryMatch,
    Latched {
        after: MatchRequirement,
        reset: ResetPolicy,
    },
}

impl FirePolicy {
    fn validate(&self) -> Result<()> {
        match self {
            Self::EveryMatch => Ok(()),
            Self::Latched { after, reset } => {
                after.validate("latched after")?;
                reset.after.validate("latched reset after")?;
                reset
                    .when
                    .validate()
                    .context("invalid latched reset condition")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResetPolicy {
    pub after: MatchRequirement,
    pub when: Condition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchRequirement {
    #[schemars(range(min = 1))]
    pub consecutive_matches: u32,
    pub minimum_seconds: u64,
}

impl MatchRequirement {
    fn validate(self, label: &str) -> Result<()> {
        if self.consecutive_matches == 0 {
            anyhow::bail!("{label} consecutive_matches must be greater than zero");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[schemars(with = "ConditionDef")]
#[serde(from = "ConditionDef", into = "ConditionDef")]
pub enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Schedule(ScheduleCondition),
    TimeWindow(TimeWindowCondition),
    WifiPower(WifiPowerCondition),
    WifiSsid(WifiSsidCondition),
    ProcessNetwork(ProcessNetworkCondition),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
enum ConditionDef {
    All(AllCondition),
    Any(AnyCondition),
    Schedule(ScheduleLeaf),
    TimeWindow(TimeWindowLeaf),
    WifiPower(WifiPowerLeaf),
    WifiSsid(WifiSsidLeaf),
    ProcessNetwork(ProcessNetworkLeaf),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "A non-empty recursive Boolean condition tree.")]
struct AllCondition {
    #[schemars(length(min = 1))]
    all: Vec<Condition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "A non-empty recursive Boolean condition tree.")]
struct AnyCondition {
    #[schemars(length(min = 1))]
    any: Vec<Condition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "A schedule leaf that emits evaluation pulses.")]
struct ScheduleLeaf {
    schedule: ScheduleCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "A half-open local-time window, including overnight windows.")]
struct TimeWindowLeaf {
    time_window: TimeWindowCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "A Wi-Fi power-state sensor condition.")]
struct WifiPowerLeaf {
    wifi_power: WifiPowerCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "A connected or visible SSID sensor condition.")]
struct WifiSsidLeaf {
    wifi_ssid: WifiSsidCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "An aggregate network-throughput condition for application bundles.")]
struct ProcessNetworkLeaf {
    process_network: ProcessNetworkCondition,
}

impl From<ConditionDef> for Condition {
    fn from(value: ConditionDef) -> Self {
        match value {
            ConditionDef::All(value) => Self::All(value.all),
            ConditionDef::Any(value) => Self::Any(value.any),
            ConditionDef::Schedule(value) => Self::Schedule(value.schedule),
            ConditionDef::TimeWindow(value) => Self::TimeWindow(value.time_window),
            ConditionDef::WifiPower(value) => Self::WifiPower(value.wifi_power),
            ConditionDef::WifiSsid(value) => Self::WifiSsid(value.wifi_ssid),
            ConditionDef::ProcessNetwork(value) => Self::ProcessNetwork(value.process_network),
        }
    }
}

impl From<Condition> for ConditionDef {
    fn from(value: Condition) -> Self {
        match value {
            Condition::All(all) => Self::All(AllCondition { all }),
            Condition::Any(any) => Self::Any(AnyCondition { any }),
            Condition::Schedule(schedule) => Self::Schedule(ScheduleLeaf { schedule }),
            Condition::TimeWindow(time_window) => Self::TimeWindow(TimeWindowLeaf { time_window }),
            Condition::WifiPower(wifi_power) => Self::WifiPower(WifiPowerLeaf { wifi_power }),
            Condition::WifiSsid(wifi_ssid) => Self::WifiSsid(WifiSsidLeaf { wifi_ssid }),
            Condition::ProcessNetwork(process_network) => {
                Self::ProcessNetwork(ProcessNetworkLeaf { process_network })
            }
        }
    }
}

impl Condition {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::All(children) | Self::Any(children) => {
                if children.is_empty() {
                    anyhow::bail!("all/any condition groups must not be empty");
                }
                for child in children {
                    child.validate()?;
                }
                Ok(())
            }
            Self::Schedule(value) => value.validate(),
            Self::TimeWindow(value) => value.validate(),
            Self::WifiPower(_) => Ok(()),
            Self::WifiSsid(value) => {
                if value.ssid.trim().is_empty() {
                    anyhow::bail!("wifi_ssid ssid must not be empty");
                }
                Ok(())
            }
            Self::ProcessNetwork(value) => value.validate(),
        }
    }

    pub fn collect_sensor_requirements(
        &self,
        ssids: &mut BTreeSet<String>,
        applications: &mut BTreeSet<String>,
        needs_wifi_power: &mut bool,
    ) {
        match self {
            Self::All(children) | Self::Any(children) => {
                for child in children {
                    child.collect_sensor_requirements(ssids, applications, needs_wifi_power);
                }
            }
            Self::WifiPower(_) => *needs_wifi_power = true,
            Self::WifiSsid(value) => {
                ssids.insert(value.ssid.clone());
            }
            Self::ProcessNetwork(value) => {
                applications.extend(value.applications.iter().cloned());
            }
            Self::Schedule(_) | Self::TimeWindow(_) => {}
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EverySecondsSchedule {
    #[schemars(range(min = 1))]
    pub every_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EveryMinutesSchedule {
    #[schemars(range(min = 1))]
    pub every_minutes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EveryHoursSchedule {
    #[schemars(range(min = 1))]
    pub every_hours: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DailyAtSchedule {
    #[serde(deserialize_with = "deserialize_string_list")]
    #[schemars(with = "StringOrStringListSchema")]
    pub daily_at: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CronSchedule {
    #[serde(deserialize_with = "deserialize_string_list")]
    #[schemars(with = "StringOrStringListSchema")]
    pub cron: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ScheduleCondition {
    EverySeconds(EverySecondsSchedule),
    EveryMinutes(EveryMinutesSchedule),
    EveryHours(EveryHoursSchedule),
    DailyAt(DailyAtSchedule),
    Cron(CronSchedule),
}

#[derive(JsonSchema)]
#[schemars(untagged)]
#[allow(dead_code)]
enum StringOrStringListSchema {
    One(String),
    Many(#[schemars(length(min = 1), extend("uniqueItems" = true))] Vec<String>),
}

impl ScheduleCondition {
    pub fn validate(&self) -> Result<()> {
        if self.interval_seconds() == Some(0) {
            anyhow::bail!("schedule interval must be greater than zero");
        }
        let timezone = self.timezone()?;
        if let ScheduleCondition::DailyAt(schedule) = self {
            if schedule.daily_at.is_empty() {
                anyhow::bail!("daily_at must not be empty");
            }
            for value in &schedule.daily_at {
                parse_time(value)?;
            }
            let unique = schedule.daily_at.iter().collect::<BTreeSet<_>>();
            if unique.len() != schedule.daily_at.len() {
                anyhow::bail!("daily_at must not contain duplicates");
            }
        }
        if let ScheduleCondition::Cron(schedule) = self {
            if schedule.cron.is_empty() {
                anyhow::bail!("cron must not be empty");
            }
            for value in &schedule.cron {
                let _: cron::Schedule = value
                    .parse()
                    .with_context(|| format!("invalid cron expression {value}"))?;
            }
            let unique = schedule.cron.iter().collect::<BTreeSet<_>>();
            if unique.len() != schedule.cron.len() {
                anyhow::bail!("cron must not contain duplicates");
            }
        }
        let _ = timezone;
        Ok(())
    }

    pub fn interval_seconds(&self) -> Option<u64> {
        match self {
            Self::EverySeconds(value) => Some(value.every_seconds),
            Self::EveryMinutes(value) => value.every_minutes.checked_mul(60),
            Self::EveryHours(value) => value.every_hours.checked_mul(60 * 60),
            Self::DailyAt(_) | Self::Cron(_) => None,
        }
    }

    pub fn timezone(&self) -> Result<Tz> {
        self.timezone_name()
            .unwrap_or("UTC")
            .parse::<Tz>()
            .with_context(|| {
                format!(
                    "invalid schedule timezone {}",
                    self.timezone_name().unwrap_or("UTC")
                )
            })
    }

    fn timezone_name(&self) -> Option<&str> {
        match self {
            Self::EverySeconds(value) => value.timezone.as_deref(),
            Self::EveryMinutes(value) => value.timezone.as_deref(),
            Self::EveryHours(value) => value.timezone.as_deref(),
            Self::DailyAt(value) => value.timezone.as_deref(),
            Self::Cron(value) => value.timezone.as_deref(),
        }
    }

    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if let Some(seconds) = self.interval_seconds() {
            let timezone = self.timezone().ok()?;
            let local_after = after.with_timezone(&timezone);
            let anchor = chrono::NaiveDate::from_ymd_opt(1970, 1, 1)?.and_hms_opt(0, 0, 0)?;
            let elapsed = local_after
                .naive_local()
                .signed_duration_since(anchor)
                .num_seconds();
            let interval = i64::try_from(seconds).ok()?;
            let next_tick = elapsed.div_euclid(interval).checked_add(1)?;
            let skipped_tick_limit = 172_800_u64.checked_div(seconds)?.saturating_add(2);
            for offset in 0..=skipped_tick_limit {
                let tick = next_tick.checked_add(i64::try_from(offset).ok()?)?;
                let candidate = anchor
                    .checked_add_signed(chrono::Duration::seconds(tick.checked_mul(interval)?))?;
                if let Some(candidate) = local_candidate_after(timezone, candidate, after) {
                    return Some(candidate);
                }
            }
            return None;
        }

        let timezone = self.timezone().ok()?;
        let local_after = after.with_timezone(&timezone);
        if let Self::DailyAt(schedule) = self {
            let mut parsed = schedule
                .daily_at
                .iter()
                .filter_map(|value| parse_time(value).ok())
                .collect::<Vec<_>>();
            parsed.sort_unstable();
            for day_offset in 0..=8 {
                let date = local_after
                    .date_naive()
                    .checked_add_days(chrono::Days::new(day_offset))?;
                for time in &parsed {
                    let raw = date.and_time(*time);
                    if let Some(candidate) = local_candidate_after(timezone, raw, after) {
                        return Some(candidate);
                    }
                }
            }
            return None;
        }

        match self {
            Self::Cron(schedule) => Some(
                schedule
                    .cron
                    .iter()
                    .filter_map(|value| value.parse::<cron::Schedule>().ok())
                    .filter_map(|value| value.after(&local_after).next())
                    .min()
                    .map(|value| value.with_timezone(&Utc)),
            )
            .flatten(),
            _ => None,
        }
    }
}

fn local_candidate_after(
    timezone: Tz,
    local: chrono::NaiveDateTime,
    after: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    match timezone.from_local_datetime(&local) {
        LocalResult::Single(value) => {
            let value = value.with_timezone(&Utc);
            (value > after).then_some(value)
        }
        LocalResult::Ambiguous(first, second) => [first, second]
            .into_iter()
            .map(|value| value.with_timezone(&Utc))
            .filter(|value| *value > after)
            .min(),
        LocalResult::None => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowCondition {
    pub timezone: String,
    #[schemars(regex(pattern = r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$"))]
    pub start: String,
    #[schemars(regex(pattern = r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$"))]
    pub end: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekdays: Option<Vec<WeekdayName>>,
}

impl TimeWindowCondition {
    fn validate(&self) -> Result<()> {
        let _: Tz = self
            .timezone
            .parse()
            .with_context(|| format!("invalid time_window timezone {}", self.timezone))?;
        parse_time(&self.start)?;
        parse_time(&self.end)?;
        if self
            .weekdays
            .as_ref()
            .is_some_and(|values| values.is_empty())
        {
            anyhow::bail!("time_window weekdays must not be empty");
        }
        if self.weekdays.as_ref().is_some_and(|values| {
            values
                .iter()
                .enumerate()
                .any(|(index, value)| values[..index].contains(value))
        }) {
            anyhow::bail!("time_window weekdays must not contain duplicates");
        }
        Ok(())
    }

    pub fn matches(&self, now: DateTime<Utc>) -> Option<bool> {
        let timezone = self.timezone.parse::<Tz>().ok()?;
        let start = parse_time(&self.start).ok()?;
        let end = parse_time(&self.end).ok()?;
        let local = now.with_timezone(&timezone);
        if let Some(weekdays) = &self.weekdays {
            if !weekdays
                .iter()
                .any(|value| value.as_weekday() == local.weekday())
            {
                return Some(false);
            }
        }
        let time = local.time();
        Some(if start <= end {
            time >= start && time < end
        } else {
            time >= start || time < end
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WeekdayName {
    Sun,
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
}

impl WeekdayName {
    fn as_weekday(self) -> Weekday {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WifiPowerCondition {
    pub state: WifiPowerState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WifiPowerState {
    On,
    Off,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WifiSsidCondition {
    #[schemars(length(min = 1))]
    pub ssid: String,
    pub state: WifiSsidState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WifiSsidState {
    Connected,
    Disconnected,
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessNetworkCondition {
    #[schemars(
        length(min = 1),
        inner(length(min = 1)),
        extend("uniqueItems" = true)
    )]
    pub applications: Vec<String>,
    pub aggregation: NetworkAggregation,
    #[schemars(range(min = 1))]
    pub at_least_bytes_per_second: u64,
}

impl ProcessNetworkCondition {
    fn validate(&self) -> Result<()> {
        if self.applications.is_empty()
            || self
                .applications
                .iter()
                .any(|value| value.trim().is_empty() || value.trim() != value)
        {
            anyhow::bail!(
                "process_network applications must be non-empty bundle names without surrounding whitespace"
            );
        }
        let unique = self
            .applications
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if unique.len() != self.applications.len() {
            anyhow::bail!("process_network applications must not contain duplicates");
        }
        if self.at_least_bytes_per_second == 0 {
            anyhow::bail!("process_network at_least_bytes_per_second must be greater than zero");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAggregation {
    Sum,
}

pub type TriggerMap = BTreeMap<String, TriggerConfig>;

fn parse_time(raw: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(raw, "%H:%M")
        .with_context(|| format!("invalid time value {raw}; expected HH:MM"))
}

fn deserialize_optional_string_list<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(
        Option::<OneOrMany>::deserialize(deserializer)?.map(|value| match value {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }),
    )
}

fn deserialize_string_list<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_string_list(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("expected a string or non-empty string list"))
}
