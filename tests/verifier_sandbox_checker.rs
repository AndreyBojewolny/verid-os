//! Независимая проверка VERIFIER для TASK-008 (песочница-оценщик).
//! Углы, не покрытые тестами Implementer: выбор базы (аномалии пропускаются,
//! усечение целочисленного допуска), отсутствие одной метрики, мусорная и
//! canary-помеченная телеметрия, taint только errors-базы, provenance базы
//! (наблюдение), отсутствие канареечных записей при гейт-отказе, ненулевая
//! errors-база, экстремальные базы (0/отрицательная/i64::MAX), раздельные
//! прогоны двух обновлений одного тика, replay/rebuild, прогоны не триггеры,
//! заглушка не пишет телеметрию.

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
    lp.submit(upd(&[], &[]), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    // Аномалия ещё и триггер: авто-обновление + поданное = 2 исполнения.
    assert_eq!(r.triggers, 1);
    assert_eq!(r.executed, 2);
    assert_eq!(reason(&journal), Some(Value::Text("non-regression".into())));
}

#[test]
fn integer_tolerance_truncates() {
    // 80 + 80*25/100 = 100: canary 100 проходит ровно.
    let mut j = Journal::new();
    baseline(&mut j, 80, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), Vec::new());
    assert_eq!(lp.tick(&mut j, &ROOT, EPOCH, 1000, None).expect("tick").executed, 1);

    // 79 + 79*25/100 = 79 + 19 = 98 (усечение): canary 100 > 98 -> откат.
    let mut j = Journal::new();
    baseline(&mut j, 79, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), Vec::new());
    let r = lp.tick(&mut j, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&j), Some(Value::Text("latency-regression".into())));
}

#[test]
fn missing_single_metric_fails_closed() {
    let mut j = Journal::new();
    tel(&mut j, 0, 900, "latency", 200, false, TaintFlags::empty()); // errors нет
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), Vec::new());
    assert_eq!(lp.tick(&mut j, &ROOT, EPOCH, 1000, None).expect("tick").rolled_back, 1);
    assert_eq!(reason(&j), Some(Value::Text("no-baseline".into())));

    let mut j = Journal::new();
    tel(&mut j, 0, 900, "errors", 0, false, TaintFlags::empty()); // latency нет
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), Vec::new());
    assert_eq!(lp.tick(&mut j, &ROOT, EPOCH, 1000, None).expect("tick").rolled_back, 1);
    assert_eq!(reason(&j), Some(Value::Text("no-baseline".into())));
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
    lp.submit(upd(&[], &[]), Vec::new());
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
    lp.submit(upd(&[], &[]), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("tainted-evidence".into())));
}

#[test]
fn untainted_cell_domain_telemetry_counts_as_baseline() {
    // НАБЛЮДЕНИЕ (OBS-1): provenance базы не ограничена доменом/актором —
    // чистая телеметрия клетки (домен 16) принимается как база. Фиксация
    // текущего поведения; ужесточение — решение владельца при интеграции
    // генератора (см. отчёт VERIFIER).
    let mut journal = Journal::new();
    tel(&mut journal, 16, 555, "latency", 200, false, TaintFlags::empty());
    tel(&mut journal, 16, 555, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
}

#[test]
fn gate_rejection_writes_no_canary_records() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&["key.sign"], &[]), Vec::new()); // overgrant без human-grant
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
    lp.submit(upd(&["x.cap"], &[]), Vec::new());
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
        lp.submit(upd(&[], &[]), Vec::new());
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
    lp.submit(upd(&[], &[]), Vec::new());
    lp.submit(upd(&[], &[]), Vec::new());
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
    lp.submit(upd(&[], &[]), Vec::new());
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
    lp.submit(upd(&[], &[]), Vec::new());
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
    lp.submit(upd(&[], &[]), Vec::new()); // canary_pass=true, базы нет — заглушке всё равно
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
    lp.submit(upd(&[], &["a.cap", "b.cap"]), Vec::new());
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
}