//! Тесты Evolution Loop v0 (TASK-004): полный цикл, 5 красных линий,
//! каскад деградации A->B->C, model_tier, детерминизм.

use std::sync::{Arc, Mutex};

use veridos_journal::evolution_loop::{
    payload, Config, EvolutionLoop, LoopStatus, ProposedUpdate, Target, Tier,
};
use veridos_journal::journal::{mac, EventKind, Journal, Record, TaintFlags, WarnSink};

const ROOT: [u8; 32] = [21u8; 32];
const EPOCH: u32 = 1;
const ACTOR: u64 = 77;

fn mk(domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, EPOCH), domain)
}

fn config(budget: u64, cost: u64) -> Config {
    Config { budget, execute_cost: cost, heartbeat_secs: 3600, actor: ACTOR }
}

fn telemetry(journal: &mut Journal, metric: &str, value: i64, anomaly: bool) -> u64 {
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::Telemetry,
        TaintFlags::empty(), Vec::new(), payload::telemetry(metric, value, anomaly),
    );
    journal.append(rec, &mk(0)).expect("telemetry append")
}

fn update(target: Target, caps_add: &[&str], canary_pass: bool) -> ProposedUpdate {
    ProposedUpdate {
        target,
        caps_add: caps_add.iter().map(|s| s.to_string()).collect(),
        caps_del: Vec::new(),
        canary_pass,
    }
}

#[derive(Clone, Default)]
struct CollectSink(Arc<Mutex<Vec<String>>>);

impl WarnSink for CollectSink {
    fn warn(&mut self, message: &str) {
        self.0.lock().unwrap().push(message.to_string());
    }
}

fn phases(journal: &Journal) -> Vec<String> {
    journal
        .iter()
        .filter(|r| r.kind == EventKind::EvolutionCycle)
        .filter_map(|r| {
            let ciborium::value::Value::Map(map) =
                ciborium::de::from_reader::<ciborium::value::Value, _>(&r.payload[..]).ok()?
            else {
                return None;
            };
            map.iter().find_map(|(k, v)| match (k, v) {
                (ciborium::value::Value::Text(key), ciborium::value::Value::Text(val)) if key == "phase" => Some(val.clone()),
                _ => None,
            })
        })
        .collect()
}

#[test]
fn full_cycle_on_synthetic_telemetry() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    telemetry(&mut journal, "latency", 500, true);
    telemetry(&mut journal, "latency", 10, false); // нормальная — не триггер

    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.triggers, 1);
    assert_eq!(report.hypotheses, 1);
    assert_eq!(report.executed, 1);
    assert_eq!(report.status, LoopStatus::Running);
    assert_eq!(report.tier, Tier::A);

    let kinds: Vec<EventKind> = journal.iter().map(|r| r.kind).collect();
    assert!(kinds.contains(&EventKind::Hypothesis));
    assert!(kinds.contains(&EventKind::CodeUpdate));
    assert!(kinds.contains(&EventKind::CanaryResult));
    assert_eq!(lp.budget_left(), 90);
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn task_end_is_trigger() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    let rec = Record::draft(
        EPOCH, 16, 0, 5, EventKind::TaskEnd, TaintFlags::empty(), Vec::new(), Vec::new(),
    );
    journal.append(rec, &mk(16)).expect("task end");
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.triggers, 1);
    assert_eq!(report.executed, 1);
}

#[test]
fn red_line_1_l0_change_freezes() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    let sink = CollectSink::default();
    lp.set_sink(Box::new(sink.clone()));
    lp.submit(update(Target::L0, &[], true));

    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.status, LoopStatus::Frozen);
    assert!(phases(&journal).contains(&"freeze".to_string()));
    assert!(sink.0.lock().unwrap().iter().any(|m| m.contains("RED LINE 1")));

    // Замороженная петля не исполняет даже разрешённые обновления.
    lp.submit(update(Target::Cell, &[], true));
    let len = journal.len();
    lp.tick(&mut journal, &ROOT, EPOCH, 2000, None).expect("tick");
    assert_eq!(journal.len(), len);
}

#[test]
fn red_line_2_state_hash_divergence_freezes_with_priority() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    let sink = CollectSink::default();
    lp.set_sink(Box::new(sink.clone()));
    telemetry(&mut journal, "latency", 500, true);
    lp.submit(update(Target::Cell, &[], true));

    let wrong_hash = [0xAAu8; 32];
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, Some(wrong_hash)).expect("tick");
    assert_eq!(report.status, LoopStatus::Frozen);
    assert_eq!(report.executed, 0); // приоритет 0: раньше любого Execute
    let kinds: Vec<EventKind> = journal.iter().map(|r| r.kind).collect();
    assert!(kinds.contains(&EventKind::Checkpoint)); // консервация журнала
    assert!(phases(&journal).contains(&"freeze".to_string()));
    assert!(sink.0.lock().unwrap().iter().any(|m| m.contains("RED LINE 2")));

    // Совпадающий якорь не замораживает.
    let mut lp2 = EvolutionLoop::new(config(100, 10));
    let mut j2 = Journal::new();
    let ok_hash = j2.state_hash();
    let report = lp2.tick(&mut j2, &ROOT, EPOCH, 1000, Some(ok_hash)).expect("tick");
    assert_eq!(report.status, LoopStatus::Running);
}

#[test]
fn red_line_3_overgrant_rollback_dlq_and_full_stop() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    let sink = CollectSink::default();
    lp.set_sink(Box::new(sink.clone()));
    for _ in 0..3 {
        lp.submit(update(Target::Cell, &["key.sign"], true));
    }

    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.rejected, 3);
    assert_eq!(report.executed, 0);
    assert_eq!(report.status, LoopStatus::Stopped);
    let dlq_count = journal.iter().filter(|r| r.kind == EventKind::DlqEntry).count();
    assert_eq!(dlq_count, 3);
    assert!(journal.iter().filter(|r| r.kind == EventKind::DlqEntry).all(|r| r.taint.contains(TaintFlags::DLQ)));
    assert!(phases(&journal).contains(&"stop".to_string()));
    assert!(sink.0.lock().unwrap().iter().any(|m| m.contains("FULL STOP")));
    // Права не расширились.
    let graph = veridos_journal::reachability::CapabilityGraph::from_journal(&journal);
    assert!(graph.capabilities(ACTOR).is_empty());
}

#[test]
fn red_line_3_loop_self_modification_is_violation() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    lp.submit(update(Target::Loop, &[], true));
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.rejected, 1);
    assert_eq!(report.executed, 0);
    assert!(phases(&journal).contains(&"violation".to_string()));
}

#[test]
fn red_line_4_three_consecutive_rollbacks_pause() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    let sink = CollectSink::default();
    lp.set_sink(Box::new(sink.clone()));
    for _ in 0..3 {
        lp.submit(update(Target::Cell, &[], false)); // canary fail
    }
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.rolled_back, 3);
    assert_eq!(report.status, LoopStatus::PausedHuman);
    assert!(phases(&journal).contains(&"pause".to_string()));
    assert!(sink.0.lock().unwrap().iter().any(|m| m.contains("RED LINE 4")));
    let canaries: Vec<_> = journal.iter().filter(|r| r.kind == EventKind::CanaryResult).collect();
    assert_eq!(canaries.len(), 3);
}

#[test]
fn successful_canary_resets_rollback_counter() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    lp.submit(update(Target::Cell, &[], false));
    lp.submit(update(Target::Cell, &[], false));
    lp.submit(update(Target::Cell, &[], true)); // сброс счётчика
    lp.submit(update(Target::Cell, &[], false));
    lp.submit(update(Target::Cell, &[], false));
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.status, LoopStatus::Running);
    assert_eq!(report.rolled_back, 4);
    assert_eq!(report.executed, 1);
}

#[test]
fn red_line_5_budget_cascade_a_b_c_with_heartbeat() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(10, 10));
    let sink = CollectSink::default();
    lp.set_sink(Box::new(sink.clone()));

    // Тик 1: исполнение съедает бюджет -> A->B.
    telemetry(&mut journal, "latency", 500, true);
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick1");
    assert_eq!(report.executed, 1);
    assert_eq!(report.tier, Tier::B);
    assert_eq!(lp.budget_left(), 0);

    // Тик 2: ярус B анализирует, но не модифицирует; гипотеза в очереди.
    telemetry(&mut journal, "errors", 7, true);
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 2000, None).expect("tick2");
    assert_eq!(report.tier, Tier::B);
    assert_eq!(report.hypotheses, 1);
    assert_eq!(report.executed, 0);
    assert_eq!(lp.hypothesis_queue().len(), 1);

    // Тик 3: новых триггеров нет -> B->C.
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 3000, None).expect("tick3");
    assert_eq!(report.tier, Tier::C);
    assert!(phases(&journal).iter().filter(|p| *p == "degrade").count() >= 2);
    assert!(sink.0.lock().unwrap().iter().any(|m| m.contains("RED LINE 5")));

    // Тик 4: heartbeat не раньше интервала.
    let len = journal.len();
    lp.tick(&mut journal, &ROOT, EPOCH, 3000 + 3599, None).expect("tick4");
    assert_eq!(journal.len(), len);
    // Тик 5: интервал вышел -> heartbeat-запись.
    lp.tick(&mut journal, &ROOT, EPOCH, 3000 + 3600, None).expect("tick5");
    assert!(phases(&journal).contains(&"heartbeat".to_string()));
}

#[test]
fn owner_resume_after_stop() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    for _ in 0..3 {
        lp.submit(update(Target::Cell, &["key.sign"], true));
    }
    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(lp.status(), LoopStatus::Stopped);

    lp.owner_resume(&mut journal, &ROOT, EPOCH).expect("resume");
    assert_eq!(lp.status(), LoopStatus::Running);
    assert!(phases(&journal).contains(&"resume".to_string()));

    // После разбора одно отклонение не останавливает петлю (счётчик сброшен).
    lp.submit(update(Target::Cell, &["key.sign"], true));
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 2000, None).expect("tick");
    assert_eq!(report.rejected, 1);
    assert_eq!(report.status, LoopStatus::Running);
}

#[test]
fn every_decision_record_carries_model_tier() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(10, 10));
    telemetry(&mut journal, "latency", 500, true);
    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    lp.tick(&mut journal, &ROOT, EPOCH, 2000, None).expect("tick");

    let mut decisions = 0;
    for rec in journal.iter() {
        if matches!(rec.kind, EventKind::Hypothesis | EventKind::CodeUpdate | EventKind::CanaryResult | EventKind::EvolutionCycle) {
            decisions += 1;
            let text = String::from_utf8_lossy(&rec.payload);
            assert!(text.contains("model_tier"), "kind {:?} без model_tier", rec.kind);
            assert!(text.contains("rules"));
        }
    }
    assert!(decisions >= 4);
}

#[test]
fn deterministic_full_cycle() {
    let run = || {
        let mut journal = Journal::new();
        let mut lp = EvolutionLoop::new(config(100, 10));
        telemetry(&mut journal, "latency", 500, true);
        lp.submit(update(Target::Cell, &["fs.read"], true));
        lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
        journal.state_hash()
    };
    assert_eq!(run(), run());
}

#[test]
fn applied_update_extends_capabilities_within_gate() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    // Ослабление+расширение невозможно без human-grant; проверяем отзыв:
    // сначала грант от владельца (домен 0), потом обновление петли его отзывает.
    let grant = Record::draft(
        EPOCH, 0, 0, ACTOR, EventKind::CapGrant, TaintFlags::empty(), Vec::new(),
        veridos_journal::reachability::encode_cap("fs.read"),
    );
    journal.append(grant, &mk(0)).expect("human grant");

    let mut upd = update(Target::Cell, &[], true);
    upd.caps_del = vec!["fs.read".to_string()];
    lp.submit(upd);
    let report = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.executed, 1);
    let graph = veridos_journal::reachability::CapabilityGraph::from_journal(&journal);
    assert!(graph.capabilities(ACTOR).is_empty());
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn tainted_telemetry_propagates_through_decisions() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    let rec = Record::draft(
        EPOCH, 0, 0, 900, EventKind::Telemetry,
        TaintFlags::EXTERNAL_NET | TaintFlags::UNVALIDATED,
        Vec::new(), payload::telemetry("latency", 500, true),
    );
    let trigger_seq = journal.append(rec, &mk(0)).expect("tainted telemetry");

    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    let hyp = journal.iter().find(|r| r.kind == EventKind::Hypothesis).expect("hypothesis");
    assert_eq!(hyp.causality, vec![trigger_seq]);
    assert!(hyp.taint.contains(TaintFlags::EXTERNAL_NET));
    assert!(hyp.taint.contains(TaintFlags::UNVALIDATED));

    let upd = journal.iter().find(|r| r.kind == EventKind::CodeUpdate).expect("update");
    assert_eq!(upd.causality, vec![hyp.seq]);
    assert!(upd.taint.contains(TaintFlags::EXTERNAL_NET));

    let canary = journal.iter().find(|r| r.kind == EventKind::CanaryResult).expect("canary");
    assert!(canary.taint.contains(TaintFlags::EXTERNAL_NET));
}

#[test]
fn tampered_journal_freezes_loop_without_writes() {
    let mut journal = Journal::new();
    telemetry(&mut journal, "latency", 500, true);
    let mut records: Vec<Record> = journal.iter().cloned().collect();
    records[0].payload[0] ^= 0x01; // подмена байта
    let mut tampered = Journal::from_records_unchecked(
        records,
        veridos_journal::journal::cas::Cas::new(),
    );

    let mut lp = EvolutionLoop::new(config(100, 10));
    let sink = CollectSink::default();
    lp.set_sink(Box::new(sink.clone()));
    let len = tampered.len();
    let report = lp.tick(&mut tampered, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(report.status, LoopStatus::Frozen);
    assert_eq!(tampered.len(), len); // консервация: журнал не тронут
    assert!(sink.0.lock().unwrap().iter().any(|m| m.contains("integrity")));
}
