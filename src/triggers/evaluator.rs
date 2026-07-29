use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::schema::{
    Condition, FirePolicy, MatchRequirement, ScheduleCondition, TriggerConfig, WifiPowerState,
    WifiSsidState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Truth {
    True,
    False,
    Unknown,
}

impl Truth {
    pub(crate) fn all(values: impl Iterator<Item = Self>) -> Self {
        let mut unknown = false;
        for value in values {
            match value {
                Self::False => return Self::False,
                Self::Unknown => unknown = true,
                Self::True => {}
            }
        }
        if unknown {
            Self::Unknown
        } else {
            Self::True
        }
    }

    pub(crate) fn any(values: impl Iterator<Item = Self>) -> Self {
        let mut unknown = false;
        for value in values {
            match value {
                Self::True => return Self::True,
                Self::Unknown => unknown = true,
                Self::False => {}
            }
        }
        if unknown {
            Self::Unknown
        } else {
            Self::False
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct WifiSnapshot {
    pub power: Option<bool>,
    pub current_ssid: Option<Option<String>>,
    pub visible_ssids: Option<BTreeSet<String>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SensorSnapshot {
    pub wifi: WifiSnapshot,
    pub application_network_bytes_per_second: BTreeMap<String, u64>,
    pub network_error: Option<String>,
}

#[derive(Clone, Debug)]
struct ScheduleRuntime {
    config: ScheduleCondition,
    next_due: Option<DateTime<Utc>>,
}

impl ScheduleRuntime {
    fn new(config: ScheduleCondition, now: DateTime<Utc>) -> Self {
        let next_due = config.next_after(now);
        Self { config, next_due }
    }

    fn evaluate(&mut self, now: DateTime<Utc>) -> Truth {
        let Some(due) = self.next_due else {
            return Truth::Unknown;
        };
        if due > now {
            return Truth::False;
        }
        self.next_due = self.config.next_after(now);
        Truth::True
    }

    fn is_due(&self, now: DateTime<Utc>) -> bool {
        self.next_due.is_some_and(|due| due <= now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerPhase {
    Armed,
    Matching,
    Pending,
    Latched,
}

impl Default for TriggerPhase {
    fn default() -> Self {
        Self::Armed
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TriggerState {
    pub phase: TriggerPhase,
    pub match_count: u32,
    pub match_started_at: Option<DateTime<Utc>>,
    pub reset_count: u32,
    pub reset_started_at: Option<DateTime<Utc>>,
    pub generation: u64,
    pub incident_id: Option<String>,
    pub last_evaluated_at: Option<DateTime<Utc>>,
    pub last_fired_at: Option<DateTime<Utc>>,
    pub last_truth: Option<Truth>,
    pub last_error: Option<String>,
    pub next_schedule_deadlines: Vec<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerDispatch {
    pub trigger_id: String,
    pub module: String,
    pub incident_id: String,
    pub fired_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct TriggerRuntime {
    id: String,
    config: TriggerConfig,
    when_schedules: Vec<ScheduleRuntime>,
    reset_schedules: Vec<ScheduleRuntime>,
    pub state: TriggerState,
}

impl TriggerRuntime {
    pub fn new(
        id: String,
        config: TriggerConfig,
        now: DateTime<Utc>,
        restored: Option<TriggerState>,
    ) -> Self {
        let when_schedules = collect_schedules(&config.when)
            .into_iter()
            .map(|value| ScheduleRuntime::new(value, now))
            .collect();
        let reset_schedules = match &config.fire {
            FirePolicy::EveryMatch => Vec::new(),
            FirePolicy::Latched { reset, .. } => collect_schedules(&reset.when)
                .into_iter()
                .map(|value| ScheduleRuntime::new(value, now))
                .collect(),
        };
        let mut runtime = Self {
            id,
            config,
            when_schedules,
            reset_schedules,
            state: restored.unwrap_or_default(),
        };
        runtime.normalize_restored_state(now);
        let restored_deadlines = runtime.state.next_schedule_deadlines.clone();
        for (schedule, deadline) in runtime
            .when_schedules
            .iter_mut()
            .chain(runtime.reset_schedules.iter_mut())
            .zip(restored_deadlines)
        {
            schedule.next_due = Some(deadline);
        }
        runtime
    }

    pub fn module(&self) -> &str {
        &self.config.module
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn config(&self) -> &TriggerConfig {
        &self.config
    }

    pub fn snapshot_state(&self) -> TriggerState {
        let mut state = self.state.clone();
        state.next_schedule_deadlines = self
            .when_schedules
            .iter()
            .chain(self.reset_schedules.iter())
            .filter_map(|schedule| schedule.next_due)
            .collect();
        state
    }

    pub fn next_wake(&self) -> Option<DateTime<Utc>> {
        let schedules = match self.state.phase {
            TriggerPhase::Armed | TriggerPhase::Matching => &self.when_schedules,
            TriggerPhase::Latched => &self.reset_schedules,
            TriggerPhase::Pending => return None,
        };
        schedules.iter().filter_map(|value| value.next_due).min()
    }

    pub fn evaluate(
        &mut self,
        now: DateTime<Utc>,
        sensors: &SensorSnapshot,
    ) -> Option<TriggerDispatch> {
        if self.state.phase == TriggerPhase::Pending {
            return None;
        }
        let evaluating_reset = self.state.phase == TriggerPhase::Latched;
        let schedules = if evaluating_reset {
            &self.reset_schedules
        } else {
            &self.when_schedules
        };
        if !schedules.is_empty() && !schedules.iter().any(|schedule| schedule.is_due(now)) {
            return None;
        }

        self.state.last_evaluated_at = Some(now);
        let active_condition = if evaluating_reset {
            match &self.config.fire {
                FirePolicy::Latched { reset, .. } => &reset.when,
                FirePolicy::EveryMatch => &self.config.when,
            }
        } else {
            &self.config.when
        };
        self.state.last_error = condition_sensor_error(active_condition, sensors);

        if self.state.phase == TriggerPhase::Latched {
            if let FirePolicy::Latched { reset, .. } = &self.config.fire {
                let truth = evaluate_condition(
                    &reset.when,
                    now,
                    sensors,
                    &mut self.reset_schedules.iter_mut(),
                );
                self.state.last_truth = Some(truth);
                update_requirement(
                    truth,
                    now,
                    reset.after,
                    &mut self.state.reset_count,
                    &mut self.state.reset_started_at,
                );
                if requirement_met(
                    reset.after,
                    self.state.reset_count,
                    self.state.reset_started_at,
                    now,
                ) {
                    self.state.phase = TriggerPhase::Armed;
                    self.state.match_count = 0;
                    self.state.match_started_at = None;
                    self.state.reset_count = 0;
                    self.state.reset_started_at = None;
                    self.state.incident_id = None;
                }
            }
            return None;
        }

        let truth = evaluate_condition(
            &self.config.when,
            now,
            sensors,
            &mut self.when_schedules.iter_mut(),
        );
        self.state.last_truth = Some(truth);

        match &self.config.fire {
            FirePolicy::EveryMatch => {
                if truth != Truth::True {
                    return None;
                }
                self.state.generation = self.state.generation.saturating_add(1);
                let incident_id = format!("{}:{}", self.id, self.state.generation);
                self.state.phase = TriggerPhase::Pending;
                self.state.incident_id = Some(incident_id.clone());
                self.state.last_fired_at = Some(now);
                Some(TriggerDispatch {
                    trigger_id: self.id.clone(),
                    module: self.config.module.clone(),
                    incident_id,
                    fired_at: now,
                })
            }
            FirePolicy::Latched { after, .. } => {
                update_requirement(
                    truth,
                    now,
                    *after,
                    &mut self.state.match_count,
                    &mut self.state.match_started_at,
                );
                if truth == Truth::True {
                    self.state.phase = TriggerPhase::Matching;
                } else {
                    self.state.phase = TriggerPhase::Armed;
                }
                if !requirement_met(
                    *after,
                    self.state.match_count,
                    self.state.match_started_at,
                    now,
                ) {
                    return None;
                }

                self.state.generation = self.state.generation.saturating_add(1);
                let incident_id = format!("{}:{}", self.id, self.state.generation);
                self.state.phase = TriggerPhase::Pending;
                self.state.incident_id = Some(incident_id.clone());
                self.state.last_fired_at = Some(now);
                Some(TriggerDispatch {
                    trigger_id: self.id.clone(),
                    module: self.config.module.clone(),
                    incident_id,
                    fired_at: now,
                })
            }
        }
    }

    pub fn mark_dispatched(&mut self, incident_id: &str) {
        if self.state.phase == TriggerPhase::Pending
            && self.state.incident_id.as_deref() == Some(incident_id)
        {
            match &self.config.fire {
                FirePolicy::EveryMatch => {
                    self.state.phase = TriggerPhase::Armed;
                    self.state.incident_id = None;
                }
                FirePolicy::Latched { .. } => self.state.phase = TriggerPhase::Latched,
            }
        }
    }

    pub fn suppress_pending(&mut self) {
        let Some(incident_id) = self.state.incident_id.clone() else {
            return;
        };
        self.mark_dispatched(&incident_id);
    }

    pub fn is_pending(&self) -> bool {
        self.state.phase == TriggerPhase::Pending
    }

    pub fn pending_dispatch(&self) -> Option<TriggerDispatch> {
        (self.state.phase == TriggerPhase::Pending).then_some(())?;
        Some(TriggerDispatch {
            trigger_id: self.id.clone(),
            module: self.config.module.clone(),
            incident_id: self.state.incident_id.clone()?,
            fired_at: self.state.last_fired_at?,
        })
    }

    fn normalize_restored_state(&mut self, now: DateTime<Utc>) {
        if matches!(&self.config.fire, FirePolicy::EveryMatch)
            && matches!(
                self.state.phase,
                TriggerPhase::Matching | TriggerPhase::Latched
            )
        {
            self.state.phase = TriggerPhase::Armed;
            self.state.match_count = 0;
            self.state.match_started_at = None;
            self.state.reset_count = 0;
            self.state.reset_started_at = None;
            self.state.incident_id = None;
        }

        if self.state.phase != TriggerPhase::Pending {
            return;
        }
        let has_incident = self
            .state
            .incident_id
            .as_deref()
            .is_some_and(|value| !value.is_empty());
        if !has_incident {
            self.state.phase = match &self.config.fire {
                FirePolicy::EveryMatch => TriggerPhase::Armed,
                FirePolicy::Latched { .. } => TriggerPhase::Latched,
            };
            self.state.incident_id = None;
            return;
        }
        if self.state.last_fired_at.is_none() {
            self.state.last_fired_at = self.state.last_evaluated_at.or(Some(now));
        }
    }
}

fn condition_sensor_error(condition: &Condition, sensors: &SensorSnapshot) -> Option<String> {
    match condition {
        Condition::All(children) | Condition::Any(children) => children
            .iter()
            .find_map(|child| condition_sensor_error(child, sensors)),
        Condition::WifiPower(_) | Condition::WifiSsid(_) => sensors.wifi.error.clone(),
        Condition::ProcessNetwork(_) => sensors.network_error.clone(),
        Condition::Schedule(_) | Condition::TimeWindow(_) => None,
    }
}

fn update_requirement(
    truth: Truth,
    now: DateTime<Utc>,
    _requirement: MatchRequirement,
    count: &mut u32,
    started_at: &mut Option<DateTime<Utc>>,
) {
    if truth == Truth::True {
        if *count == 0 {
            *started_at = Some(now);
        }
        *count = count.saturating_add(1);
    } else {
        *count = 0;
        *started_at = None;
    }
}

fn requirement_met(
    requirement: MatchRequirement,
    count: u32,
    started_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    if count < requirement.consecutive_matches {
        return false;
    }
    started_at.is_some_and(|value| {
        now.signed_duration_since(value).num_seconds()
            >= i64::try_from(requirement.minimum_seconds).unwrap_or(i64::MAX)
    })
}

fn collect_schedules(condition: &Condition) -> Vec<ScheduleCondition> {
    let mut out = Vec::new();
    match condition {
        Condition::All(children) | Condition::Any(children) => {
            for child in children {
                out.extend(collect_schedules(child));
            }
        }
        Condition::Schedule(value) => out.push(value.clone()),
        _ => {}
    }
    out
}

fn evaluate_condition<'a>(
    condition: &Condition,
    now: DateTime<Utc>,
    sensors: &SensorSnapshot,
    schedules: &mut impl Iterator<Item = &'a mut ScheduleRuntime>,
) -> Truth {
    match condition {
        Condition::All(children) => {
            let values = children
                .iter()
                .map(|child| evaluate_condition(child, now, sensors, schedules))
                .collect::<Vec<_>>();
            Truth::all(values.into_iter())
        }
        Condition::Any(children) => {
            let values = children
                .iter()
                .map(|child| evaluate_condition(child, now, sensors, schedules))
                .collect::<Vec<_>>();
            Truth::any(values.into_iter())
        }
        Condition::Schedule(_) => schedules
            .next()
            .map_or(Truth::Unknown, |value| value.evaluate(now)),
        Condition::TimeWindow(value) => value.matches(now).map_or(Truth::Unknown, Truth::from),
        Condition::WifiPower(value) => sensors.wifi.power.map_or(Truth::Unknown, |power| {
            Truth::from(matches!(
                (value.state, power),
                (WifiPowerState::On, true) | (WifiPowerState::Off, false)
            ))
        }),
        Condition::WifiSsid(value) => match value.state {
            WifiSsidState::Connected | WifiSsidState::Disconnected => sensors
                .wifi
                .current_ssid
                .as_ref()
                .map_or(Truth::Unknown, |current| {
                    let connected = current.as_deref() == Some(value.ssid.as_str());
                    Truth::from(if matches!(value.state, WifiSsidState::Connected) {
                        connected
                    } else {
                        !connected
                    })
                }),
            WifiSsidState::Available | WifiSsidState::Unavailable => sensors
                .wifi
                .visible_ssids
                .as_ref()
                .map_or(Truth::Unknown, |visible| {
                    let available = visible.contains(&value.ssid);
                    Truth::from(if matches!(value.state, WifiSsidState::Available) {
                        available
                    } else {
                        !available
                    })
                }),
        },
        Condition::ProcessNetwork(value) => {
            if sensors.network_error.is_some() {
                return Truth::Unknown;
            }
            let total = value.applications.iter().fold(0_u64, |total, application| {
                total.saturating_add(
                    sensors
                        .application_network_bytes_per_second
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case(application))
                        .map(|(_, bytes)| *bytes)
                        .fold(0_u64, u64::saturating_add),
                )
            });
            Truth::from(total >= value.at_least_bytes_per_second)
        }
    }
}

impl From<bool> for Truth {
    fn from(value: bool) -> Self {
        if value {
            Self::True
        } else {
            Self::False
        }
    }
}
