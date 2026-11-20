//! Независимая проверка VERIFIER для TASK-008 (песочница-оценщик).
//! Углы, не покрытые тестами Implementer: выбор базы (аномалии пропускаются,
//! усечение целочисленного допуска), отсутствие одной метрики, мусорная и
//! canary-помеченная телеметрия, taint только errors-базы, provenance базы
//! (TASK-009: только домен 0), отсутствие канареечных записей при гейт-отказе,
//! ненулевая errors-база, экстремальные базы (0/отрицательная/i64::MAX),
//! раздельные прогоны двух обновлений одного тика, replay/rebuild, прогоны
//! не триггеры, заглушка не пишет телеметрию.

use ciborium::value::Value;
use veridos_journal::evolution_loop::{
    payload, Config, EvolutionLoop, MetricsSandbox, ProposedUpdate, RulesSandbox, Target,
};
use veridos_journal::journal::{cas::Cas, mac, EventKind, Journal, Record, TaintFlags};

const ROOT: [u8; 32] = [71u8; 32];
const EPOCH: u32 = 2;
const ACTOR: u64 = 141;

fn mk(domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, EPOCH), domain)
}

fn config(pct: u64) -> Config {
    Config { budget: 100, execute_cost: 10, heartbeat_secs: 3600, actor: ACTOR, latency_tolerance_pct: pct }
}

fn tel(journal: &mut Journal, domain: u8, actor: u64, metric: &str, value: i64, anomaly: bool, taint: TaintFlags) -> u64 {
    let rec = Record::draft(
        EPOCH, domain, journal.len() as u64, actor, EventKind::Telemetry,
        taint, Vec::new(), payload::telemetry(metric, value, anomaly),
    );
    journal.append(rec, &mk(domain)).expect("telemetry")
}

fn baseline(journal: &mut Journal, latency: i64, errors: i64) {
    tel(journal, 0, 900, "latency", latency, false, TaintFlags::empty());
    tel(journal, 0, 900, "errors", errors, false, TaintFlags::empty());
}

/// Чистый триггер-якорь для обязательной родословной submit (TASK-009).
/// McpResponse не триггерит Monitor — счётчики тика не меняются.
fn anchor(journal: &mut Journal) -> u64 {
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::McpResponse,
        TaintFlags::empty(), Vec::new(), Vec::new(),
    );
    journal.append(rec, &mk(0)).expect("anchor")
}

fn grant(journal: &mut Journal, cap: &str) {
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, ACTOR, EventKind::CapGrant,
        TaintFlags::empty(), Vec::new(), veridos_journal::reachability::encode_cap(cap),
    );
    journal.append(rec, &mk(0)).expect("human grant");
}

fn upd(caps_add: &[&str], caps_del: &[&str]) -> ProposedUpdate {
    ProposedUpdate {
        target: Target::Cell,
        caps_add: caps_add.iter().map(|s| s.to_string()).collect(),
        caps_del: caps_del.iter().map(|s| s.to_string()).collect(),
        canary_pass: true,
    }
}

fn field(payload_bytes: &[u8], key: &str) -> Option<Value> {
    let Value::Map(map) = ciborium::de::from_reader::<Value, _>(payload_bytes).ok()? else {
        return None;
    };
    map.iter().find(|(k, _)| matches!(k, Value::Text(s) if s == key)).map(|(_, v)| v.clone())
}

fn reason(journal: &Journal) -> Option<Value> {
    let canary = journal.iter().filter(|r| r.kind == EventKind::CanaryResult).last()?;
    field(&canary.payload, "reason")
}

#[test]
fn anomaly_records_are_skipped_for_baseline() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    tel(&mut journal, 0, 900, "latency", 999, true, TaintFlags::empty()); // аномалия — не база
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    // Аномалия ещё и триггер: авто-обновление + поданное = 2 исполнения.
    assert_eq!(r.triggers, 1);
    assert_eq!(r.executed, 2);
    assert_eq!(reason(&journal), Some(Value::Text("non-regression".into())));
}

#[test]
fn integer_tolerance_truncates() {
    // 80 + 80*25/100 = 100: canary 100 проходит ровно.
    let mut journal = Journal::new();
    baseline(&mut journal, 80, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    assert_eq!(lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick").executed, 1);

    // 79 + 79*25/100 = 79 + 19 = 98 (усечение): canary 100 > 98 -> откат.
    let mut journal = Journal::new();
    baseline(&mut journal, 79, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("latency-regression".into())));
}

#[test]
fn missing_single_metric_fails_closed() {
    let mut journal = Journal::new();
    tel(&mut journal, 0, 900, "latency", 200, false, TaintFlags::empty()); // errors нет
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    assert_eq!(lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick").rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));

    let mut journal = Journal::new();
    tel(&mut journal, 0, 900, "errors", 0, false, TaintFlags::empty()); // latency нет
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    assert_eq!(lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick").rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));
}

#[test]
fn malformed_and_canary_marked_telemetry_are_not_baseline() {
    let mut journal = Journal::new();
    // Мусорный payload.
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::Telemetry,
        TaintFlags::empty(), Vec::new(), vec![0xff, 0x01],
    );
    journal.append(rec, &mk(0)).expect("garbage");
    // Canary-помеченная нормальная запись — не фоновая база.
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::Telemetry,
        TaintFlags::empty(), Vec::new(), payload::canary_telemetry("latency", 200),
    );
    journal.append(rec, &mk(0)).expect("canary-marked");
    // Маркер canary неверного типа — запись невалидна как метрика.
    let bad_type = {
        let map = Value::Map(vec![
            (Value::Text("metric".into()), Value::Text("latency".into())),
            (Value::Text("value".into()), Value::Integer(200.into())),
            (Value::Text("anomaly".into()), Value::Integer(0.into())),
            (Value::Text("canary".into()), Value::Text("yes".into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).expect("cbor");
        buf
    };
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::Telemetry,
        TaintFlags::empty(), Vec::new(), bad_type,
    );
    journal.append(rec, &mk(0)).expect("bad canary type");
    tel(&mut journal, 0, 900, "errors", 0, false, TaintFlags::empty());

    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));
}

#[test]
fn tainted_errors_baseline_alone_fails_closed() {
    let mut journal = Journal::new();
    tel(&mut journal, 0, 900, "latency", 200, false, TaintFlags::empty());
    tel(&mut journal, 0, 900, "errors", 0, false, TaintFlags::UNVALIDATED);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("tainted-evidence".into())));
}

#[test]
fn untainted_cell_domain_telemetry_is_not_baseline() {
    // TASK-009 (закрытие OBS-1): provenance базы ограничена доменом 0 —
    // чистая телеметрия клетки (домен 16) свидетельством не является:
    // нет домен-0 базы -> fail-closed откат.
    let mut journal = Journal::new();
    tel(&mut journal, 16, 555, "latency", 200, false, TaintFlags::empty());
    tel(&mut journal, 16, 555, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(r.executed, 0);
    assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));
}

#[test]
fn gate_rejection_writes_no_canary_records() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&["key.sign"], &[]), vec![anchor(&mut journal)]).expect("submit"); // overgrant без human-grant
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rejected, 1);
    let upd_rec = journal.iter().find(|r| r.kind == EventKind::CodeUpdate).expect("update");
    // Checker не вызывался: ни прогонов, ни CanaryResult.
    assert!(!journal.iter().any(|r| r.kind == EventKind::Telemetry && r.causality == vec![upd_rec.seq]));
    assert!(!journal.iter().any(|r| r.kind == EventKind::CanaryResult));
    assert!(journal.iter().any(|r| r.kind == EventKind::DlqEntry));
}

#[test]
fn nonzero_errors_baseline_allows_human_granted_expansion() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 2);
    grant(&mut journal, "x.cap");
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&["x.cap"], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1); // errors_canary=1 <= 2, latency 125 <= 250
    let upd_rec = journal.iter().find(|r| r.kind == EventKind::CodeUpdate).expect("update");
    let applied = journal
        .iter()
        .find(|r| r.kind == EventKind::CapGrant && r.domain == 16)
        .expect("applied grant");
    assert_eq!(applied.causality, vec![upd_rec.seq]);
    let graph = veridos_journal::reachability::CapabilityGraph::from_journal(&journal);
    assert!(graph.capabilities(ACTOR).contains("x.cap"));
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn extreme_baselines_fail_closed() {
    for (latency, expected) in [
        (0i64, "latency-regression"),
        (-100, "latency-regression"),
        (i64::MAX, "invalid-baseline"), // переполнение допуска
    ] {
        let mut journal = Journal::new();
        baseline(&mut journal, latency, 0);
        let mut lp = EvolutionLoop::new(config(25));
        lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
        let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
        assert_eq!(r.rolled_back, 1, "база {latency}");
        assert_eq!(reason(&journal), Some(Value::Text(expected.into())), "база {latency}");
        journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
    }
}

#[test]
fn each_update_gets_own_run_records_in_one_tick() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 2);
    let updates: Vec<&Record> = journal.iter().filter(|r| r.kind == EventKind::CodeUpdate).collect();
    assert_eq!(updates.len(), 2);
    for u in &updates {
        let runs: Vec<&Record> = journal
            .iter()
            .filter(|r| r.kind == EventKind::Telemetry && r.causality == vec![u.seq])
            .collect();
        assert_eq!(runs.len(), 2, "прогон обновления {}", u.seq);
    }
    let canaries: Vec<&Record> = journal.iter().filter(|r| r.kind == EventKind::CanaryResult).collect();
    assert_eq!(canaries.len(), 2);
    for (c, u) in canaries.iter().zip(updates.iter()) {
        assert_eq!(field(&c.payload, "update_seq"), Some(Value::Integer((u.seq as i64).into())));
        assert_eq!(c.causality, vec![u.seq]);
    }
}

#[test]
fn replay_and_rebuild_preserve_checker_state() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    tel(&mut journal, 0, 900, "latency", 500, true, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");

    let hash = journal.state_hash();
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain");
    journal.replay(0).expect("replay");
    assert_eq!(journal.state_hash(), hash);
    let rebuilt = Journal::from_records_unchecked(journal.iter().cloned().collect(), Cas::new());
    assert_eq!(rebuilt.state_hash(), hash);
    rebuilt.verify_chain(0..rebuilt.len() as u64, &ROOT).expect("rebuilt chain");
}

#[test]
fn canary_runs_do_not_become_next_tick_triggers() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick1");
    assert_eq!(r.executed, 1);
    let len = journal.len();
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 2000, None).expect("tick2");
    assert_eq!(r.triggers, 0);
    assert_eq!(r.hypotheses, 0);
    assert_eq!(journal.len(), len);
}

#[test]
fn rules_sandbox_writes_no_telemetry_and_null_evidence() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    lp.set_sandbox(Box::new(RulesSandbox));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit"); // canary_pass=true, базы нет — заглушке всё равно
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
    assert!(!journal.iter().any(|rec| rec.kind == EventKind::Telemetry));
    let canary = journal.iter().find(|rec| rec.kind == EventKind::CanaryResult).expect("canary");
    assert_eq!(field(&canary.payload, "reason"), Some(Value::Text("self-reported".into())));
    for key in ["latency_base", "latency_canary", "errors_base", "errors_canary"] {
        assert_eq!(field(&canary.payload, key), Some(Value::Null), "поле {key}");
    }
}

#[test]
fn injected_metrics_sandbox_honors_its_own_tolerance() {
    // set_sandbox заменяет default: допуск инъекции (50%) действует вместо
    // Config (25%): база 100, два изменения -> canary 150 <= 150 проходит.
    let mut journal = Journal::new();
    baseline(&mut journal, 100, 0);
    grant(&mut journal, "a.cap");
    grant(&mut journal, "b.cap");
    let mut lp = EvolutionLoop::new(config(25));
    lp.set_sandbox(Box::new(MetricsSandbox::new(50)));
    lp.submit(upd(&[], &["a.cap", "b.cap"]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
}

// --- Повторная проверка фикса AUD-1: строгие флаги anomaly/canary. ---

fn raw(metric: &str, value: i64, anomaly: i64, canary: Option<i64>) -> Vec<u8> {
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

fn append_raw(journal: &mut Journal, domain: u8, payload_bytes: Vec<u8>) -> u64 {
    let rec = Record::draft(
        EPOCH, domain, journal.len() as u64, 900, EventKind::Telemetry,
        TaintFlags::empty(), Vec::new(), payload_bytes,
    );
    journal.append(rec, &mk(domain)).expect("raw telemetry")
}

#[test]
fn negative_and_huge_flags_are_invalid() {
    for anomaly in [-1i64, 2, i64::MAX] {
        let mut journal = Journal::new();
        append_raw(&mut journal, 0, raw("latency", 1_000_000, anomaly, None));
        tel(&mut journal, 0, 900, "errors", 0, false, TaintFlags::empty());
        let mut lp = EvolutionLoop::new(config(25));
        lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
        let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
        assert_eq!(r.triggers, 0, "anomaly={anomaly} не триггер");
        assert_eq!(r.rolled_back, 1, "anomaly={anomaly} не база");
        assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));
    }
    for canary in [-1i64, 2, i64::MAX] {
        let mut journal = Journal::new();
        append_raw(&mut journal, 0, raw("latency", 200, 0, Some(canary)));
        tel(&mut journal, 0, 900, "errors", 0, false, TaintFlags::empty());
        let mut lp = EvolutionLoop::new(config(25));
        lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
        let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
        assert_eq!(r.rolled_back, 1, "canary={canary} не фон");
        assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));
    }
}

#[test]
fn parser_unit_strict_flags() {
    assert_eq!(payload::telemetry_metric(&raw("latency", 5, 0, None)), Some(("latency".into(), 5, false, false)));
    assert_eq!(payload::telemetry_metric(&raw("latency", 5, 1, None)), Some(("latency".into(), 5, true, false)));
    assert_eq!(payload::telemetry_metric(&raw("latency", 5, 0, Some(0))), Some(("latency".into(), 5, false, false)));
    assert_eq!(payload::telemetry_metric(&raw("latency", 5, 0, Some(1))), Some(("latency".into(), 5, false, true)));
    for anomaly in [-1i64, 2, 3, i64::MAX, i64::MIN] {
        assert_eq!(payload::telemetry_metric(&raw("latency", 5, anomaly, None)), None, "anomaly={anomaly}");
        assert_eq!(payload::telemetry_anomaly(&raw("latency", 5, anomaly, None)), None);
    }
    for canary in [-1i64, 2, i64::MAX] {
        assert_eq!(payload::telemetry_metric(&raw("latency", 5, 0, Some(canary))), None, "canary={canary}");
    }
}

#[test]
fn canary_anomaly_record_triggers_but_is_not_baseline() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    // Внешняя запись anomaly=1 canary=1: триггерит Monitor, но базой не является.
    append_raw(&mut journal, 0, raw("latency", 999, 1, Some(1)));
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.triggers, 1);
    assert_eq!(r.executed, 2); // авто-обновление + поданное, оба по чистой базе
    assert_eq!(reason(&journal), Some(Value::Text("non-regression".into())));
}

#[test]
fn invalid_flag_cell_telemetry_cannot_authorize() {
    // Связка OBS-1 + AUD-1 закрыта для невалидных флагов: клеточная телеметрия
    // с anomaly=2 и огромной latency не создаёт базу.
    let mut journal = Journal::new();
    append_raw(&mut journal, 16, raw("latency", 1_000_000, 2, None));
    tel(&mut journal, 16, 555, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}