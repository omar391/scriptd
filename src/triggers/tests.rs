use std::collections::{BTreeMap, BTreeSet};

use chrono::{TimeZone, Utc};

use super::schema::{DailyAtSchedule, ScheduleCondition};
use super::*;

fn parse_rule(yaml: &str) -> TriggerConfig {
    let rule: TriggerConfig = serde_yaml::from_str(yaml).expect("valid trigger yaml");
    rule.validate().expect("valid trigger");
    rule
}

fn at(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 30, 0, 0, 0)
        .single()
        .expect("valid time")
        + chrono::Duration::seconds(i64::from(second))
}

fn sensors(
    current: Option<&str>,
    visible: &[&str],
    codex_network_bytes_per_second: u64,
) -> SensorSnapshot {
    SensorSnapshot {
        wifi: WifiSnapshot {
            power: Some(true),
            current_ssid: Some(current.map(str::to_string)),
            visible_ssids: Some(visible.iter().map(|value| value.to_string()).collect()),
            error: None,
        },
        application_network_bytes_per_second: BTreeMap::from([(
            "Codex".to_string(),
            codex_network_bytes_per_second,
        )]),
        network_error: None,
    }
}

fn miwatch_rule() -> TriggerConfig {
    parse_rule(
        r#"
enabled: true
module: miwatch
fire:
  mode: latched
  after:
    consecutive_matches: 3
    minimum_seconds: 60
  reset:
    after:
      consecutive_matches: 2
      minimum_seconds: 30
    when:
      all:
        - wifi_ssid: { ssid: knight_riders_5G, state: connected }
        - wifi_ssid: { ssid: knight_riders_5G, state: available }
when:
  all:
    - schedule: { every_seconds: 30 }
    - wifi_ssid: { ssid: knight_riders_5G, state: unavailable }
    - any:
        - time_window:
            timezone: UTC
            start: "00:00"
            end: "01:00"
        - process_network:
            applications: [Codex]
            aggregation: sum
            at_least_bytes_per_second: 1024
"#,
    )
}

#[test]
fn parser_rejects_empty_boolean_group() {
    let config: TriggerConfig = serde_yaml::from_str(
        r#"
enabled: true
module: miwatch
fire: { mode: every_match }
when: { all: [] }
"#,
    )
    .expect("parse shape");
    assert!(config.validate().is_err());
}

#[test]
fn parser_rejects_unknown_trigger_field() {
    let error = serde_yaml::from_str::<TriggerConfig>(
        r#"
enabled: true
module: miwatch
surprise: true
fire: { mode: every_match }
when: { schedule: { every_seconds: 30 } }
"#,
    )
    .expect_err("unknown field");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn unavailable_ssid_fires_after_three_sustained_schedule_matches() {
    let mut runtime =
        TriggerRuntime::new("miwatch-outage".to_string(), miwatch_rule(), at(0), None);
    let snapshot = sensors(None, &[], 0);

    assert!(runtime.evaluate(at(30), &snapshot).is_none());
    assert!(runtime.evaluate(at(59), &snapshot).is_none());
    assert!(runtime.evaluate(at(60), &snapshot).is_none());
    let dispatch = runtime
        .evaluate(at(90), &snapshot)
        .expect("third due match fires");
    assert_eq!(dispatch.module, "miwatch");
    assert_eq!(runtime.state.phase, TriggerPhase::Pending);
}

#[test]
fn unavailable_ssid_outside_window_requires_codex_network_activity() {
    let mut inactive =
        TriggerRuntime::new("miwatch-outage".to_string(), miwatch_rule(), at(3600), None);
    let inactive_snapshot = sensors(None, &[], 1023);
    for second in [3630, 3660, 3690, 3720] {
        assert!(inactive.evaluate(at(second), &inactive_snapshot).is_none());
    }

    let mut active =
        TriggerRuntime::new("miwatch-outage".to_string(), miwatch_rule(), at(3600), None);
    let active_snapshot = sensors(None, &[], 1024);
    assert!(active.evaluate(at(3630), &active_snapshot).is_none());
    assert!(active.evaluate(at(3660), &active_snapshot).is_none());
    assert!(active.evaluate(at(3690), &active_snapshot).is_some());
}

#[test]
fn unknown_wifi_does_not_match_unavailable() {
    let mut runtime =
        TriggerRuntime::new("miwatch-outage".to_string(), miwatch_rule(), at(0), None);
    let snapshot = SensorSnapshot {
        wifi: WifiSnapshot {
            power: Some(true),
            current_ssid: None,
            visible_ssids: None,
            error: Some("scan failed".to_string()),
        },
        ..SensorSnapshot::default()
    };
    for second in [30, 60, 90, 120] {
        assert!(runtime.evaluate(at(second), &snapshot).is_none());
    }
    assert_eq!(runtime.state.last_truth, Some(Truth::Unknown));
}

#[test]
fn latched_incident_rearms_only_after_connected_and_visible_reset() {
    let mut runtime =
        TriggerRuntime::new("miwatch-outage".to_string(), miwatch_rule(), at(0), None);
    let unavailable = sensors(None, &[], 0);
    for second in [30, 60] {
        assert!(runtime.evaluate(at(second), &unavailable).is_none());
    }
    let dispatch = runtime.evaluate(at(90), &unavailable).expect("dispatch");
    runtime.mark_dispatched(&dispatch.incident_id);
    assert_eq!(
        runtime.next_wake(),
        None,
        "inactive outage schedules must not spin a latched trigger"
    );

    let visible_only = sensors(None, &["knight_riders_5G"], 0);
    for second in [120, 150] {
        assert!(runtime.evaluate(at(second), &visible_only).is_none());
    }
    assert_eq!(runtime.state.phase, TriggerPhase::Latched);

    let recovered = sensors(Some("knight_riders_5G"), &["knight_riders_5G"], 0);
    assert!(runtime.evaluate(at(180), &recovered).is_none());
    assert_eq!(runtime.state.phase, TriggerPhase::Latched);
    assert!(runtime.evaluate(at(210), &recovered).is_none());
    assert_eq!(runtime.state.phase, TriggerPhase::Armed);
}

#[test]
fn three_valued_logic_is_fail_closed() {
    assert_eq!(
        Truth::all([Truth::True, Truth::Unknown].into_iter()),
        Truth::Unknown
    );
    assert_eq!(
        Truth::all([Truth::Unknown, Truth::False].into_iter()),
        Truth::False
    );
    assert_eq!(
        Truth::any([Truth::False, Truth::Unknown].into_iter()),
        Truth::Unknown
    );
    assert_eq!(
        Truth::any([Truth::Unknown, Truth::True].into_iter()),
        Truth::True
    );
}

#[test]
fn short_circuited_boolean_branches_do_not_misalign_schedule_runtimes() {
    let rule = parse_rule(
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when:
  all:
    - any:
        - wifi_power: { state: on }
        - schedule: { every_seconds: 10 }
    - schedule: { every_seconds: 30 }
"#,
    );
    let mut runtime = TriggerRuntime::new("aligned".to_string(), rule, at(0), None);
    let snapshot = SensorSnapshot {
        wifi: WifiSnapshot {
            power: Some(true),
            ..WifiSnapshot::default()
        },
        ..SensorSnapshot::default()
    };

    assert!(runtime.evaluate(at(10), &snapshot).is_none());
    assert!(runtime.evaluate(at(30), &snapshot).is_some());
}

#[test]
fn wifi_snapshot_example_uses_independent_connected_and_visible_facts() {
    let snapshot = sensors(None, &["knight_riders_5G"], 0);
    assert_eq!(snapshot.wifi.current_ssid, Some(None));
    assert_eq!(
        snapshot.wifi.visible_ssids,
        Some(BTreeSet::from(["knight_riders_5G".to_string()]))
    );
}

#[test]
fn parser_accepts_every_supported_leaf_and_nested_groups() {
    let rule = parse_rule(
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when:
  any:
    - schedule: { daily_at: ["05:00", "17:00"], timezone: Asia/Dhaka }
    - schedule: { cron: ["0 0 * * * *"], timezone: UTC }
    - time_window:
        timezone: Asia/Dhaka
        start: "22:00"
        end: "02:00"
        weekdays: [mon, tue]
    - wifi_power: { state: on }
    - wifi_ssid: { ssid: test, state: connected }
    - wifi_ssid: { ssid: test, state: disconnected }
    - wifi_ssid: { ssid: test, state: available }
    - wifi_ssid: { ssid: test, state: unavailable }
    - process_network:
        applications: [Codex]
        aggregation: sum
        at_least_bytes_per_second: 1024
"#,
    );
    let rendered = serde_yaml::to_string(&rule).expect("serialize trigger");
    parse_rule(&rendered);
}

#[test]
fn daily_schedule_skips_a_nonexistent_dst_wall_time() {
    let schedule = ScheduleCondition::DailyAt(DailyAtSchedule {
        daily_at: vec!["02:30".to_string()],
        timezone: Some("America/New_York".to_string()),
    });
    let after = Utc
        .with_ymd_and_hms(2026, 3, 7, 12, 0, 0)
        .single()
        .expect("fixed time");
    let next = schedule.next_after(after).expect("next valid daily time");
    let local = next.with_timezone(&chrono_tz::America::New_York);

    assert_eq!(local.date_naive().to_string(), "2026-03-09");
    assert_eq!(local.time().format("%H:%M").to_string(), "02:30");
}

#[test]
fn parser_rejects_invalid_timezone_time_cron_threshold_and_latch_policy() {
    for yaml in [
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { time_window: { timezone: Mars/Olympus, start: "00:00", end: "01:00" } }
"#,
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { time_window: { timezone: UTC, start: "25:00", end: "01:00" } }
"#,
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { schedule: { cron: ["not cron"] } }
"#,
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { process_network: { applications: [Codex], aggregation: sum, at_least_bytes_per_second: 0 } }
"#,
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { schedule: { daily_at: ["05:00", "05:00"] } }
"#,
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { process_network: { applications: [Codex, codex], aggregation: sum, at_least_bytes_per_second: 1024 } }
"#,
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { time_window: { timezone: UTC, start: "00:00", end: "01:00", weekdays: [mon, mon] } }
"#,
        r#"
enabled: true
module: mcpu
fire:
  mode: latched
  after: { consecutive_matches: 0, minimum_seconds: 0 }
  reset:
    after: { consecutive_matches: 1, minimum_seconds: 0 }
    when: { wifi_power: { state: on } }
when: { wifi_power: { state: off } }
"#,
    ] {
        let result = serde_yaml::from_str::<TriggerConfig>(yaml)
            .map_err(anyhow::Error::from)
            .and_then(|config| config.validate());
        assert!(result.is_err(), "invalid trigger unexpectedly accepted");
    }
}

#[test]
fn parser_rejects_unknown_nested_leaf_field() {
    let result = serde_yaml::from_str::<TriggerConfig>(
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when:
  wifi_ssid:
    ssid: test
    state: available
    typo: true
"#,
    );
    assert!(result.is_err());
}

#[test]
fn overnight_window_is_start_inclusive_and_end_exclusive() {
    let rule = parse_rule(
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when:
  time_window:
    timezone: UTC
    start: "05:00"
    end: "02:00"
"#,
    );
    let base = Utc
        .with_ymd_and_hms(2026, 7, 30, 0, 0, 0)
        .single()
        .expect("base");
    for (seconds, expected) in [
        (5 * 3600, true),
        (24 * 3600 + 3600 + 59 * 60 + 59, true),
        (24 * 3600 + 2 * 3600, false),
        (24 * 3600 + 4 * 3600 + 59 * 60, false),
    ] {
        let now = base + chrono::Duration::seconds(seconds);
        let mut runtime = TriggerRuntime::new("window".to_string(), rule.clone(), base, None);
        let fired = runtime.evaluate(now, &SensorSnapshot::default()).is_some();
        assert_eq!(fired, expected, "unexpected result at {now}");
    }
}

#[test]
fn network_activity_alone_cannot_authorize_miwatch() {
    let network_alone = sensors(Some("knight_riders_5G"), &["knight_riders_5G"], 500_000);
    let mut runtime =
        TriggerRuntime::new("miwatch-outage".to_string(), miwatch_rule(), at(0), None);
    for second in [30, 60, 90, 120] {
        assert!(runtime.evaluate(at(second), &network_alone).is_none());
    }
}

#[test]
fn unknown_network_observation_outside_window_fails_closed() {
    let mut runtime =
        TriggerRuntime::new("miwatch-outage".to_string(), miwatch_rule(), at(3600), None);
    let mut snapshot = sensors(None, &[], 0);
    snapshot.network_error = Some("nettop unavailable".to_string());
    for second in [3630, 3660, 3690, 3720] {
        assert!(runtime.evaluate(at(second), &snapshot).is_none());
    }
    assert_eq!(runtime.state.last_truth, Some(Truth::Unknown));
}

#[test]
fn pending_and_latched_incidents_restore_without_duplicate_generation() {
    let rule = miwatch_rule();
    let mut runtime = TriggerRuntime::new("miwatch-outage".to_string(), rule.clone(), at(0), None);
    let unavailable = sensors(None, &[], 0);
    for second in [30, 60] {
        assert!(runtime.evaluate(at(second), &unavailable).is_none());
    }
    let dispatch = runtime
        .evaluate(at(90), &unavailable)
        .expect("initial dispatch");
    let saved_pending = runtime.snapshot_state();

    let mut restored = TriggerRuntime::new(
        "miwatch-outage".to_string(),
        rule.clone(),
        at(91),
        Some(saved_pending),
    );
    assert_eq!(restored.pending_dispatch().as_ref(), Some(&dispatch));
    assert!(restored.evaluate(at(120), &unavailable).is_none());
    assert_eq!(restored.state.phase, TriggerPhase::Pending);
    restored.mark_dispatched(&dispatch.incident_id);

    let restored_latched = TriggerRuntime::new(
        "miwatch-outage".to_string(),
        rule,
        at(121),
        Some(restored.snapshot_state()),
    );
    assert!(restored_latched.pending_dispatch().is_none());
    assert_eq!(restored_latched.state.generation, 1);
    assert_eq!(restored_latched.state.phase, TriggerPhase::Latched);
}

#[test]
fn suppressing_a_pending_latched_dispatch_consumes_it_without_rearming() {
    let rule = miwatch_rule();
    let mut runtime = TriggerRuntime::new("miwatch-outage".to_string(), rule, at(0), None);
    let unavailable = sensors(None, &[], 0);
    for second in [30, 60] {
        assert!(runtime.evaluate(at(second), &unavailable).is_none());
    }
    assert!(runtime.evaluate(at(90), &unavailable).is_some());

    runtime.suppress_pending();

    assert!(runtime.pending_dispatch().is_none());
    assert_eq!(runtime.state.phase, TriggerPhase::Latched);
    assert_eq!(runtime.state.generation, 1);
}

#[test]
fn incompatible_every_match_reload_does_not_restore_a_latched_phase() {
    let rule = parse_rule(
        r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { schedule: { every_minutes: 1 } }
"#,
    );
    let restored = TriggerState {
        phase: TriggerPhase::Latched,
        generation: 4,
        incident_id: Some("old-outage:4".to_string()),
        ..TriggerState::default()
    };

    let runtime = TriggerRuntime::new("sample".to_string(), rule, at(0), Some(restored));

    assert_eq!(runtime.state.phase, TriggerPhase::Armed);
    assert_eq!(runtime.state.generation, 4);
    assert!(runtime.state.incident_id.is_none());
}
