//! Тесты песочницы-оценщика TASK-008: независимость checker'а от самооценки
//! генератора, fail-closed (нет базы / tainted-база), граница допуска,
//! errors-регресс, родословная канареечной телеметрии, детерминизм.

use ciborium::value::Value;
use veridos_journal::evolution_loop::{
    payload, Config, EvolutionLoop, LoopStatus, MetricsSandbox, ProposedUpdate, RulesSandbox, Target,
};
use veridos_journal::journal::{mac, EventKind, Journal, Record, TaintFlags, WarnSink};

const ROOT: [u8; 32] = [61u8; 32];
const EPOCH: u32 = 1;
const ACTOR: u64 = 123;

fn mk(domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, EPOCH), domain)
}

fn config(pct: u64) -> Config {
    Config { budget: 100, execute_cost: 10, heartbeat_secs: 3600, actor: ACTOR, latency_tolerance_pct: pct }
}

fn telemetry(journal: &mut Journal, metric: &str, value: i64, anomaly: bool, taint: TaintFlags) -> u64 {
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::Telemetry,
        taint, Vec::new(), payload::telemetry(metric, value, anomaly),
    );
    journal.append(rec, &mk(0)).expect("telemetry")
}

fn baseline(journal: &mut Journal, latency: i64) {
    telemetry(journal, "latency", latency, false, TaintFlags::empty());
    telemetry(journal, "errors", 0, false, TaintFlags::empty());
}

fn human_grant(journal: &mut Journal, cap: &str) {
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, ACTOR, EventKind::CapGrant,
        TaintFlags::empty(), Vec::new(), veridos_journal::reachability::encode_cap(cap),
    );
    journal.append(rec, &mk(0)).expect("human grant");
}

fn update(caps_add: &[&str], caps_del: &[&str], canary_pass: bool) -> ProposedUpdate {
    ProposedUpdate {
        target: Target::Cell,
        caps_add: caps_add.iter().map(|s| s.to_string()).collect(),
        caps_del: caps_del.iter().map(|s| s.to_string()).collect(),
        canary_pass,
    }
}

fn field(payload_bytes: &[u8], key: &str) -> Option<Value> {
    let Value::Map(map) = ciborium::de::from_reader::<Value, _>(payload_bytes).ok()? else {
        return None;
    };
    map.iter().find(|(k, _)| matches!(k, Value::Text(s) if s == key)).map(|(_, v)| v.clone())
}

fn canary_of(journal: &Journal) -> &Record {
    journal.iter().filter(|r| r.kind == EventKind::CanaryResult).last().expect("canary result")
}

#[derive(Clone, Default)]
struct CollectSink(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl WarnSink for CollectSink {
    fn warn(&mut self, message: &str) {
        self.0.lock().unwrap().push(message.to_string());
    }
}

#[test]
fn checker_ignores_self_reported_verdict() {
    // canary_pass=true, но базы нет -> fail-closed откат.
    let mut j = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut j, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(r.executed, 0);

    // canary_pass=false, но метрики в норме -> применяется.
    let mut j = Journal::new();
    baseline(&mut j, 200);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], false), Vec::new());
    let r = lp.tick(&mut j, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
    assert_eq!(r.rolled_back, 0);
}

#[test]
fn missing_baseline_fails_closed() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    let canary = canary_of(&journal);
    assert_eq!(field(&canary.payload, "passed"), Some(Value::Integer(0.into())));
    assert_eq!(field(&canary.payload, "reason"), Some(Value::Text("no-baseline".into())));
    // Симулированный прогон всё равно журналируется.
    let upd = journal.iter().find(|r| r.kind == EventKind::CodeUpdate).expect("update");
    let run: Vec<&Record> = journal
        .iter()
        .filter(|r| r.kind == EventKind::Telemetry && r.causality == vec![upd.seq])
        .collect();
    assert_eq!(run.len(), 2);
}

#[test]
fn tainted_baseline_fails_closed() {
    let mut journal = Journal::new();
    telemetry(&mut journal, "latency", 200, false, TaintFlags::EXTERNAL_NET);
    telemetry(&mut journal, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    let sink = CollectSink::default();
    lp.set_sink(Box::new(sink.clone()));
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(r.executed, 0);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("tainted-evidence".into())));
    assert!(sink.0.lock().unwrap().iter().any(|m| m.contains("tainted-evidence")));
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn tolerance_boundary_exact_passes() {
    let mut journal = Journal::new();
    baseline(&mut journal, 100); // порог = 100 + 25% = 125
    human_grant(&mut journal, "a.cap");
    let mut lp = EvolutionLoop::new(config(25));
    // Одно изменение capability: latency_canary = 100 + 25 = 125 — ровно граница.
    lp.submit(update(&[], &["a.cap"], false), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("non-regression".into())));
    assert!(journal.iter().any(|r| r.kind == EventKind::CapRevoke));
}

#[test]
fn tolerance_boundary_above_fails() {
    let mut journal = Journal::new();
    baseline(&mut journal, 100);
    human_grant(&mut journal, "a.cap");
    human_grant(&mut journal, "b.cap");
    let mut lp = EvolutionLoop::new(config(25));
    // Два изменения: latency_canary = 150 > 125.
    lp.submit(update(&[], &["a.cap", "b.cap"], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("latency-regression".into())));
    // Отзыв не применён.
    assert!(!journal.iter().any(|r| r.kind == EventKind::CapRevoke));
    let graph = veridos_journal::reachability::CapabilityGraph::from_journal(&journal);
    assert!(graph.capabilities(ACTOR).contains("a.cap"));
    assert!(graph.capabilities(ACTOR).contains("b.cap"));
}

#[test]
fn errors_regression_rejects_even_within_latency_tolerance() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200);
    human_grant(&mut journal, "x.cap");
    let mut lp = EvolutionLoop::new(config(25));
    // latency_canary = 125 <= 250, но errors_canary = 1 > базы 0.
    lp.submit(update(&["x.cap"], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("errors-regression".into())));
    // Грант петли (домен 16) не записан: право только от human-grant.
    assert!(!journal.iter().any(|r| r.kind == EventKind::CapGrant && r.domain == 16));
}

#[test]
fn canary_telemetry_carries_update_lineage() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    let upd = journal.iter().find(|r| r.kind == EventKind::CodeUpdate).expect("update");
    let run: Vec<&Record> = journal
        .iter()
        .filter(|r| r.kind == EventKind::Telemetry && r.causality == vec![upd.seq])
        .collect();
    assert_eq!(run.len(), 2);
    for rec in run {
        assert_eq!(rec.domain, 0);
        assert!(rec.taint.is_empty());
        let (metric, value, anomaly, canary) = payload::telemetry_metric(&rec.payload).expect("metric");
        assert!(!anomaly);
        assert!(canary, "запись прогона помечена canary=1");
        match metric.as_str() {
            "latency" => assert_eq!(value, 100),
            "errors" => assert_eq!(value, 0),
            other => panic!("неожиданная метрика {other}"),
        }
    }
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn tolerance_comes_from_config() {
    let mut journal = Journal::new();
    baseline(&mut journal, 100);
    human_grant(&mut journal, "a.cap");
    let mut lp = EvolutionLoop::new(config(25));
    // Нулевой допуск: 125 > 100 -> откат, хотя default 25% прошёл бы.
    lp.set_sandbox(Box::new(MetricsSandbox::new(0)));
    lp.submit(update(&[], &["a.cap"], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("latency-regression".into())));
}

#[test]
fn canary_result_records_measured_evidence() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    let canary = canary_of(&journal);
    assert_eq!(field(&canary.payload, "passed"), Some(Value::Integer(1.into())));
    assert_eq!(field(&canary.payload, "latency_base"), Some(Value::Integer(200.into())));
    assert_eq!(field(&canary.payload, "latency_canary"), Some(Value::Integer(100.into())));
    assert_eq!(field(&canary.payload, "errors_base"), Some(Value::Integer(0.into())));
    assert_eq!(field(&canary.payload, "errors_canary"), Some(Value::Integer(0.into())));
    assert_eq!(field(&canary.payload, "model_tier"), Some(Value::Text("rules".into())));
}

#[test]
fn rules_sandbox_is_explicit_opt_in_only() {
    // Заглушка подключается явно и слушает самооценку генератора.
    let mut journal = Journal::new();
    baseline(&mut journal, 200);
    let mut lp = EvolutionLoop::new(config(25));
    lp.set_sandbox(Box::new(RulesSandbox));
    lp.submit(update(&[], &[], false), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("self-reported".into())));
}

#[test]
fn tainted_background_telemetry_poisons_baseline_until_clean() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick1");
    assert_eq!(r.executed, 1);

    // Tainted-фоновое измерение становится последней нормальной записью
    // метрики -> следующее обновление fail-closed.
    telemetry(&mut journal, "latency", 200, false, TaintFlags::EXTERNAL_NET);
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 2000, None).expect("tick2");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("tainted-evidence".into())));

    // Свежая чистая телеметрия восстанавливает базу.
    baseline(&mut journal, 200);
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 3000, None).expect("tick3");
    assert_eq!(r.executed, 1);
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn canary_run_records_are_not_baseline() {
    // Без фоновой базы все обновления fail-closed: измерения собственных
    // прогонов checker'а не создают базу (иначе петля сама себя авторизует).
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 2);
    assert_eq!(r.executed, 0);
}

#[test]
fn deterministic_with_checker() {
    let run = || {
        let mut journal = Journal::new();
        baseline(&mut journal, 200);
        telemetry(&mut journal, "latency", 500, true, TaintFlags::empty());
        let mut lp = EvolutionLoop::new(config(25));
        lp.submit(update(&[], &[], true), Vec::new());
        lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
        journal.state_hash()
    };
    assert_eq!(run(), run());
}

#[test]
fn three_fail_closed_rollbacks_pause_loop() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    for _ in 0..3 {
        lp.submit(update(&[], &[], true), Vec::new());
    }
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 3);
    assert_eq!(r.status, LoopStatus::PausedHuman);
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

// --- Регрессия AUD-1: флаги anomaly/canary вне {0,1} невалидны (fail-closed). ---

fn raw_telemetry(metric: &str, value: i64, anomaly: i64, canary: Option<i64>) -> Vec<u8> {
    let mut entries = vec![
        (Value::Text("metric".into()), Value::Text(metric.into())),
        (Value::Text("value".into()), Value::Integer(value.into())),
        (Value::Text("anomaly".into()), Value::Integer(anomaly.into())),
    ];
    if let Some(c) = canary {
        entries.push((Value::Text("canary".into()), Value::Integer(c.into())));
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).expect("cbor");
    buf
}

fn append_raw(journal: &mut Journal, payload_bytes: Vec<u8>) -> u64 {
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::Telemetry,
        TaintFlags::empty(), Vec::new(), payload_bytes,
    );
    journal.append(rec, &mk(0)).expect("raw telemetry")
}

#[test]
fn anomaly_flag_outside_01_is_invalid() {
    let mut journal = Journal::new();
    // anomaly=2: не триггер и не база (даже с огромным значением).
    append_raw(&mut journal, raw_telemetry("latency", 1_000_000, 2, None));
    telemetry(&mut journal, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.triggers, 0);
    assert_eq!(r.rolled_back, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("no-baseline".into())));
}

#[test]
fn canary_flag_outside_01_is_invalid() {
    let mut journal = Journal::new();
    // canary=2: запись невалидна, фоновой базой не становится.
    append_raw(&mut journal, raw_telemetry("latency", 200, 0, Some(2)));
    telemetry(&mut journal, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(field(&canary_of(&journal).payload, "reason"), Some(Value::Text("no-baseline".into())));
}

#[test]
fn explicit_canary_zero_is_background() {
    let mut journal = Journal::new();
    // canary=0 — валидный фоновый маркер: база принимается.
    append_raw(&mut journal, raw_telemetry("latency", 200, 0, Some(0)));
    telemetry(&mut journal, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(update(&[], &[], true), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
}