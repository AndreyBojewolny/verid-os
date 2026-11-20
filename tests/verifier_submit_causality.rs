//! Независимая проверка VERIFIER для TASK-007 (causality в submit()).
//! Углы, не покрытые тестами Implementer: мульти-родительский OR и транзитивный
//! taint, родословная при overgrant-отказе и L0-заморозке, FIFO со смешанной
//! родословной, taint canary при регрессе, частичное исполнение очереди при
//! неизвестном родителе второго предложения.

use veridos_journal::evolution_loop::{Config, EvolutionLoop, LoopStatus, ProposedUpdate, Target};
use veridos_journal::journal::{mac, AppendError, EventKind, Journal, Record, TaintFlags};

const ROOT: [u8; 32] = [53u8; 32];
const EPOCH: u32 = 1;
const ACTOR: u64 = 99;

fn mk(domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, EPOCH), domain)
}

fn config() -> Config {
    Config { budget: 100, execute_cost: 10, heartbeat_secs: 60, actor: ACTOR }
}

fn cell_update(canary_pass: bool) -> ProposedUpdate {
    ProposedUpdate { target: Target::Cell, caps_add: Vec::new(), caps_del: Vec::new(), canary_pass }
}

fn tainted_trigger(journal: &mut Journal, source_seq: u64, taint: TaintFlags) -> u64 {
    let rec = Record::draft(
        EPOCH, 0, source_seq, 900, EventKind::McpResponse, taint, Vec::new(), Vec::new(),
    );
    journal.append(rec, &mk(0)).expect("trigger")
}

#[test]
fn multi_parent_lineage_or_and_transitive_taint() {
    let mut journal = Journal::new();
    let gp = tainted_trigger(&mut journal, 0, TaintFlags::EXTERNAL_NET);
    let parent = Record::draft(
        EPOCH, 0, 1, 900, EventKind::AgentDecision, TaintFlags::LLM_OUTPUT, vec![gp], Vec::new(),
    );
    let p = journal.append(parent, &mk(0)).expect("parent");
    assert!(journal.get(p).unwrap().taint.contains(TaintFlags::EXTERNAL_NET));
    let clean = journal
        .append(Record::draft(EPOCH, 0, 2, 900, EventKind::TaskStart, TaintFlags::empty(), Vec::new(), Vec::new()), &mk(0))
        .expect("clean");

    let mut lp = EvolutionLoop::new(config());
    lp.submit(cell_update(true), vec![p, clean]);
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
    let upd = journal.iter().find(|rec| rec.kind == EventKind::CodeUpdate).expect("update");
    assert_eq!(upd.causality, vec![p, clean]);
    assert!(upd.taint.contains(TaintFlags::EXTERNAL_NET), "транзитивный taint деда");
    assert!(upd.taint.contains(TaintFlags::LLM_OUTPUT));
}

#[test]
fn rejected_overgrant_keeps_lineage_on_code_update() {
    let mut journal = Journal::new();
    let t = tainted_trigger(&mut journal, 0, TaintFlags::EXTERNAL_NET);
    let mut lp = EvolutionLoop::new(config());
    let mut proposal = cell_update(true);
    proposal.caps_add = vec!["key.sign".to_string()];
    lp.submit(proposal, vec![t]);
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rejected, 1);
    assert_eq!(r.status, LoopStatus::Running);
    let upd = journal.iter().find(|rec| rec.kind == EventKind::CodeUpdate).expect("update");
    assert_eq!(upd.causality, vec![t]);
    assert!(upd.taint.contains(TaintFlags::EXTERNAL_NET));
    assert!(journal.iter().any(|rec| rec.kind == EventKind::DlqEntry));
}

#[test]
fn l0_attempt_with_lineage_still_freezes_before_record() {
    let mut journal = Journal::new();
    let t = tainted_trigger(&mut journal, 0, TaintFlags::L2_UNTRUSTED);
    let mut lp = EvolutionLoop::new(config());
    lp.submit(
        ProposedUpdate { target: Target::L0, caps_add: Vec::new(), caps_del: Vec::new(), canary_pass: true },
        vec![t],
    );
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.status, LoopStatus::Frozen);
    assert!(!journal.iter().any(|rec| rec.kind == EventKind::CodeUpdate));
}

#[test]
fn fifo_mixed_lineage_order_preserved() {
    let mut journal = Journal::new();
    let t1 = tainted_trigger(&mut journal, 0, TaintFlags::EXTERNAL_NET);
    let t2 = tainted_trigger(&mut journal, 1, TaintFlags::L2_UNTRUSTED);
    let mut lp = EvolutionLoop::new(config());
    lp.submit(cell_update(true), vec![t1]);
    lp.submit(cell_update(true), vec![t2]);
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 2);
    let updates: Vec<&Record> = journal.iter().filter(|rec| rec.kind == EventKind::CodeUpdate).collect();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].causality, vec![t1]);
    assert!(updates[0].taint.contains(TaintFlags::EXTERNAL_NET));
    assert!(!updates[0].taint.contains(TaintFlags::L2_UNTRUSTED));
    assert_eq!(updates[1].causality, vec![t2]);
    assert!(updates[1].taint.contains(TaintFlags::L2_UNTRUSTED));
    assert!(!updates[1].taint.contains(TaintFlags::EXTERNAL_NET));
}

#[test]
fn canary_failure_with_lineage_taints_canary_record() {
    let mut journal = Journal::new();
    let t = tainted_trigger(&mut journal, 0, TaintFlags::LLM_OUTPUT | TaintFlags::UNVALIDATED);
    let mut lp = EvolutionLoop::new(config());
    lp.submit(cell_update(false), vec![t]);
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    let upd = journal.iter().find(|rec| rec.kind == EventKind::CodeUpdate).expect("update");
    let canary = journal.iter().find(|rec| rec.kind == EventKind::CanaryResult).expect("canary");
    assert_eq!(canary.causality, vec![upd.seq]);
    assert!(canary.taint.contains(TaintFlags::LLM_OUTPUT));
    assert!(canary.taint.contains(TaintFlags::UNVALIDATED));
}

#[test]
fn unknown_parent_second_item_first_applies_and_chain_stays_valid() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config());
    lp.submit(cell_update(true), Vec::new());
    lp.submit(cell_update(true), vec![999]);
    let result = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None);
    assert_eq!(result, Err(AppendError::UnknownParent(999)));
    // Первое предложение исполнено, второе отклонено до мутации; цепочка валидна.
    assert_eq!(journal.iter().filter(|rec| rec.kind == EventKind::CodeUpdate).count(), 1);
    assert_eq!(journal.iter().filter(|rec| rec.kind == EventKind::CanaryResult).count(), 1);
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn dlq_inherits_lineage_taint_end_to_end() {
    let mut journal = Journal::new();
    let t = tainted_trigger(&mut journal, 0, TaintFlags::EXTERNAL_NET | TaintFlags::UNVALIDATED);
    let mut lp = EvolutionLoop::new(config());
    let mut proposal = cell_update(true);
    proposal.caps_add = vec!["key.sign".to_string()];
    lp.submit(proposal, vec![t]);
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rejected, 1);
    let upd = journal.iter().find(|rec| rec.kind == EventKind::CodeUpdate).expect("update");
    let dlq = journal.iter().find(|rec| rec.kind == EventKind::DlqEntry).expect("dlq");
    assert_eq!(dlq.causality, vec![upd.seq]);
    assert!(dlq.taint.contains(TaintFlags::DLQ));
    assert!(dlq.taint.contains(TaintFlags::EXTERNAL_NET));
    assert!(dlq.taint.contains(TaintFlags::UNVALIDATED));
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}