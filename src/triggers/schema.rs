use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, LocalResult, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetPolicy {
    pub after: MatchRequirement,
    pub when: Condition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchRequirement {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllCondition {
    all: Vec<Condition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyCondition {
    any: Vec<Condition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleLeaf {
    schedule: ScheduleCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeWindowLeaf {
    time_window: TimeWindowCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WifiPowerLeaf {
    wifi_power: WifiPowerCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WifiSsidLeaf {
    wifi_ssid: WifiSsidCondition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleCondition {
    #[serde(default)]
    pub every_seconds: Option<u64>,
    #[serde(default)]
    pub every_minutes: Option<u64>,
    #[serde(default)]
    pub every_hours: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_string_list")]
    pub daily_at: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_string_list")]
    pub cron: Option<Vec<String>>,
    #[serde(default)]
    pub timezone: Option<String>,
}

impl ScheduleCondition {
    pub fn validate(&self) -> Result<()> {
        let count = [
            self.every_seconds.is_some(),
            self.every_minutes.is_some(),
            self.every_hours.is_some(),
            self.daily_at.is_some(),
            self.cron.is_some(),
        ]
        .into_iter()
        .filter(|value| *value)
        .count();
        if count != 1 {
            anyhow::bail!(
                "schedule must define exactly one of every_seconds/every_minutes/every_hours/daily_at/cron"
            );
        }

        if self.interval_seconds() == Some(0) {
            anyhow::bail!("schedule interval must be greater than zero");
        }
        if (self.every_seconds.is_some()
            || self.every_minutes.is_some()
            || self.every_hours.is_some())
            && self.interval_seconds().is_none()
        {
            anyhow::bail!("schedule interval is too large");
        }
        let timezone = self.timezone()?;
        if let Some(values) = &self.daily_at {
            if values.is_empty() {
                anyhow::bail!("daily_at must not be empty");
            }
            for value in values {
                parse_time(value)?;
            }
        }
        if let Some(values) = &self.cron {
            if values.is_empty() {
                anyhow::bail!("cron must not be empty");
            }
            for value in values {
                let _: cron::Schedule = value
                    .parse()
                    .with_context(|| format!("invalid cron expression {value}"))?;
            }
        }
        let _ = timezone;
        Ok(())
    }

    pub fn interval_seconds(&self) -> Option<u64> {
        self.every_seconds
            .or_else(|| self.every_minutes.and_then(|value| value.checked_mul(60)))
            .or_else(|| {
                self.every_hours
                    .and_then(|value| value.checked_mul(60 * 60))
            })
    }

    pub fn timezone(&self) -> Result<Tz> {
        self.timezone
            .as_deref()
            .unwrap_or("UTC")
            .parse::<Tz>()
            .with_context(|| {
                format!(
                    "invalid schedule timezone {}",
                    self.timezone.as_deref().unwrap_or("UTC")
                )
            })
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
        if let Some(times) = &self.daily_at {
            let mut parsed = times
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

        self.cron.as_ref().and_then(|values| {
            values
                .iter()
                .filter_map(|value| value.parse::<cron::Schedule>().ok())
                .filter_map(|value| value.after(&local_after).next())
                .min()
                .map(|value| value.with_timezone(&Utc))
        })
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowCondition {
    pub timezone: String,
    pub start: String,
    pub end: String,
    #[serde(default)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiPowerCondition {
    pub state: WifiPowerState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WifiPowerState {
    On,
    Off,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiSsidCondition {
    pub ssid: String,
    pub state: WifiSsidState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WifiSsidState {
    Connected,
    Disconnected,
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessNetworkCondition {
    pub applications: Vec<String>,
    pub aggregation: NetworkAggregation,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
