//! Независимая проверка VERIFIER для TASK-004 (Evolution Loop v0).
//! Адверсариальные углы, не покрытые тестами Implementer: разделение эпох
//! красной линии 3, приоритет линии 2 над линией 1, откат реально не применяет
//! изменения, бюджет не тратится на отклонённые, мусорная телеметрия,
//! дедупликация триггеров, model_tier через CBOR-разбор, целостность после каскада.

use ciborium::value::Value;
use veridos_journal::evolution_loop::{payload, Config, EvolutionLoop, LoopStatus, ProposedUpdate, Target, Tier};
use veridos_journal::journal::{mac, EventKind, Journal, Record, TaintFlags};
use veridos_journal::reachability::CapabilityGraph;

const ROOT: [u8; 32] = [31u8; 32];
const ACTOR: u64 = 88;

fn mk(epoch: u32, domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, epoch), domain)
}

fn config(budget: u64, cost: u64) -> Config {
    Config { budget, execute_cost: cost, heartbeat_secs: 60, actor: ACTOR }
}

fn anomaly(journal: &mut Journal, epoch: u32) -> u64 {
    let rec = Record::draft(
        epoch, 0, journal.len() as u64, 901, EventKind::Telemetry,
        TaintFlags::empty(), Vec::new(), payload::telemetry("cpu", 99, true),
    );
    journal.append(rec, &mk(epoch, 0)).expect("telemetry")
}

fn upd(target: Target, caps_add: &[&str], caps_del: &[&str], canary_pass: bool) -> ProposedUpdate {
    ProposedUpdate {
        target,
        caps_add: caps_add.iter().map(|s| s.to_string()).collect(),
        caps_del: caps_del.iter().map(|s| s.to_string()).collect(),
        canary_pass,
    }
}

fn field(payload_bytes: &[u8], key: &str) -> Option<String> {
    let Value::Map(map) = ciborium::de::from_reader::<Value, _>(payload_bytes).ok()? else {
        return None;
    };
    map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Text(v)) if k == key => Some(v.clone()),
        _ => None,
    })
}

#[test]
fn overgrant_attempts_are_per_epoch() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    // 2 попытки в эпохе 1.
    lp.submit(upd(Target::Cell, &["key.sign"], &[], true));
    lp.submit(upd(Target::Cell, &["key.sign"], &[], true));
    let r = lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick e1");
    assert_eq!(r.rejected, 2);
    assert_eq!(r.status, LoopStatus::Running);
    // 1 попытка в эпохе 2: суммарно 3, но счётчик по эпохе — не останавливать.
    lp.submit(upd(Target::Cell, &["key.sign"], &[], true));
    let r = lp.tick(&mut journal, &ROOT, 2, 2000, None).expect("tick e2");
    assert_eq!(r.rejected, 1);
    assert_eq!(r.status, LoopStatus::Running);
}

#[test]
fn state_hash_divergence_outranks_l0_attempt() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    lp.submit(upd(Target::L0, &[], &[], true));
    let r = lp.tick(&mut journal, &ROOT, 1, 1000, Some([0xBB; 32])).expect("tick");
    assert_eq!(r.status, LoopStatus::Frozen);
    let freeze_details: Vec<String> = journal
        .iter()
        .filter(|rec| rec.kind == EventKind::EvolutionCycle)
        .filter_map(|rec| field(&rec.payload, "detail"))
        .collect();
    assert!(freeze_details.iter().any(|d| d.contains("state_hash")));
    assert!(!freeze_details.iter().any(|d| d.contains("L0")));
    // Консервация: checkpoint присутствует.
    assert!(journal.iter().any(|rec| rec.kind == EventKind::Checkpoint));
}

#[test]
fn l0_attempt_writes_no_code_update_record() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    lp.submit(upd(Target::L0, &[], &[], true));
    lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick");
    assert!(!journal.iter().any(|rec| rec.kind == EventKind::CodeUpdate));
}

#[test]
fn canary_rollback_really_prevents_capability_change() {
    let mut journal = Journal::new();
    let grant = Record::draft(
        1, 0, 0, ACTOR, EventKind::CapGrant, TaintFlags::empty(), Vec::new(),
        veridos_journal::reachability::encode_cap("fs.read"),
    );
    journal.append(grant, &mk(1, 0)).expect("human grant");

    let mut lp = EvolutionLoop::new(config(100, 10));
    lp.submit(upd(Target::Cell, &[], &["fs.read"], false)); // отзыв, но canary fail
    let r = lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(r.executed, 0);
    // Отзыв не применён: capability у актора осталась.
    let graph = CapabilityGraph::from_journal(&journal);
    assert!(graph.capabilities(ACTOR).contains("fs.read"));
    assert!(!journal.iter().any(|rec| rec.kind == EventKind::CapRevoke));
}

#[test]
fn rejected_updates_do_not_consume_budget() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    lp.submit(upd(Target::Cell, &["key.sign"], &[], true)); // overgrant -> reject
    lp.submit(upd(Target::Cell, &[], &[], false)); // canary fail -> rollback
    let r = lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick");
    assert_eq!(r.rejected, 1);
    assert_eq!(r.rolled_back, 1);
    assert_eq!(lp.budget_left(), 100);
    assert_eq!(lp.tier(), Tier::A);
}

#[test]
fn malformed_telemetry_is_not_a_trigger() {
    let mut journal = Journal::new();
    let rec = Record::draft(
        1, 0, 0, 901, EventKind::Telemetry, TaintFlags::empty(), Vec::new(), vec![0xff, 0x01],
    );
    journal.append(rec, &mk(1, 0)).expect("append");
    let mut lp = EvolutionLoop::new(config(100, 10));
    let r = lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick");
    assert_eq!(r.triggers, 0);
    assert_eq!(r.hypotheses, 0);
    assert_eq!(r.executed, 0);
}

#[test]
fn redelivered_telemetry_triggers_once() {
    let mut journal = Journal::new();
    let seq1 = anomaly(&mut journal, 1);
    // Повторная доставка того же события (тот же source_seq) — дедуп журнала.
    let rec = Record::draft(
        1, 0, seq1, 901, EventKind::Telemetry, TaintFlags::empty(), Vec::new(),
        payload::telemetry("cpu", 99, true),
    );
    let seq2 = journal.append(rec, &mk(1, 0)).expect("redelivery");
    assert_eq!(seq1, seq2);

    let mut lp = EvolutionLoop::new(config(100, 10));
    let r = lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick");
    assert_eq!(r.triggers, 1);
    assert_eq!(r.executed, 1);
}

#[test]
fn pause_blocks_until_owner_resume_and_resets_counter() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    for _ in 0..3 {
        lp.submit(upd(Target::Cell, &[], &[], false));
    }
    lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick");
    assert_eq!(lp.status(), LoopStatus::PausedHuman);

    // Пауза блокирует исполнение.
    lp.submit(upd(Target::Cell, &[], &[], true));
    let len = journal.len();
    lp.tick(&mut journal, &ROOT, 1, 2000, None).expect("tick paused");
    assert_eq!(journal.len(), len);

    lp.owner_resume(&mut journal, &ROOT, 1).expect("resume");
    // Счётчик откатов сброшен: 2 неудачи после resume не ставят на паузу.
    lp.submit(upd(Target::Cell, &[], &[], false));
    lp.submit(upd(Target::Cell, &[], &[], false));
    let r = lp.tick(&mut journal, &ROOT, 1, 3000, None).expect("tick after resume");
    assert_eq!(r.rolled_back, 2);
    assert_eq!(r.status, LoopStatus::Running);
}

#[test]
fn model_tier_present_via_cbor_decode() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(10, 10));
    anomaly(&mut journal, 1);
    lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick1");
    lp.tick(&mut journal, &ROOT, 1, 2000, None).expect("tick2");
    lp.tick(&mut journal, &ROOT, 1, 3000, None).expect("tick3");

    let mut decisions = 0;
    for rec in journal.iter() {
        if matches!(rec.kind, EventKind::Hypothesis | EventKind::CodeUpdate | EventKind::CanaryResult | EventKind::EvolutionCycle) {
            decisions += 1;
            assert_eq!(field(&rec.payload, "model_tier").as_deref(), Some("rules"), "kind {:?}", rec.kind);
        }
    }
    assert!(decisions >= 5);
}

#[test]
fn chain_and_replay_intact_after_full_cascade() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(10, 10));
    anomaly(&mut journal, 1);
    lp.tick(&mut journal, &ROOT, 1, 1000, None).expect("tick1"); // execute + A->B
    anomaly(&mut journal, 1);
    lp.tick(&mut journal, &ROOT, 1, 2000, None).expect("tick2"); // B analysis
    lp.tick(&mut journal, &ROOT, 1, 3000, None).expect("tick3"); // B->C
    lp.tick(&mut journal, &ROOT, 1, 3060, None).expect("tick4"); // heartbeat
    assert_eq!(lp.tier(), Tier::C);

    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain after cascade");
    let hash = journal.state_hash();
    journal.replay(0).expect("replay");
    assert_eq!(journal.state_hash(), hash);
}

#[test]
fn no_heartbeat_outside_tier_c() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(100, 10));
    lp.tick(&mut journal, &ROOT, 1, 100_000, None).expect("tick");
    assert!(!journal.iter().any(|rec| {
        rec.kind == EventKind::EvolutionCycle && field(&rec.payload, "phase").as_deref() == Some("heartbeat")
    }));
}