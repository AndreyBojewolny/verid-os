//! Независимая проверка VERIFIER для TASK-003 (reachability v0).
//! Не дублирует тесты Implementer: смешанные акторы, частичное покрытие
//! human-grant, идемпотентность, мусорный payload, replay-детерминизм,
//! мутация байта, наследование DLQ-taint, семантика окна surface.

use veridos_journal::journal::cas::Cas;
use veridos_journal::journal::{mac, AppendError, EventKind, Journal, Record, TaintFlags, VerifyError};
use veridos_journal::reachability::{
    gate_code_update, overgrant_diff, overgrant_surface, CapabilityGraph, GateVerdict,
};
use veridos_journal::reachability::graph::encode_cap;

const ROOT: [u8; 32] = [11u8; 32];
const EPOCH: u32 = 3;

fn key(domain: u8) -> [u8; 32] {
    let mut epoch_key = mac::epoch_key(&ROOT, EPOCH);
    let k = mac::mac_key(&epoch_key, domain);
    mac::zeroize_key(&mut epoch_key);
    k
}

fn append(journal: &mut Journal, domain: u8, actor: u64, kind: EventKind, payload: Vec<u8>) -> u64 {
    let rec = Record::draft(
        EPOCH,
        domain,
        journal.len() as u64,
        actor,
        kind,
        TaintFlags::empty(),
        Vec::new(),
        payload,
    );
    journal.append(rec, &key(domain)).expect("append")
}

fn grant(journal: &mut Journal, domain: u8, actor: u64, cap: &str) -> u64 {
    append(journal, domain, actor, EventKind::CapGrant, encode_cap(cap))
}

#[test]
fn mixed_actors_diff_isolates_expansion() {
    let mut before_j = Journal::new();
    grant(&mut before_j, 16, 1, "fs.read");
    grant(&mut before_j, 16, 2, "net.fetch");
    let before = CapabilityGraph::from_journal(&before_j);

    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "fs.read");
    grant(&mut after_j, 16, 1, "key.sign"); // расширение актора 1
    // актор 2 полностью теряет права
    let after = CapabilityGraph::from_journal(&after_j);

    let diff = overgrant_diff(&before, &after);
    assert!(diff.expanded);
    assert_eq!(diff.added, vec![(1, "key.sign".into())]);
}

#[test]
fn partial_human_coverage_rejects_only_unauthorized() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    let before = CapabilityGraph::from_journal(&journal);

    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "fs.read");
    grant(&mut after_j, 0, 1, "cap.a"); // human-grant
    grant(&mut after_j, 16, 1, "cap.b"); // без human-grant
    let after = CapabilityGraph::from_journal(&after_j);

    let update_seq = append(&mut journal, 16, 1, EventKind::CodeUpdate, encode_cap("update"));
    let verdict = gate_code_update(&mut journal, &key(0), EPOCH, 1, update_seq, &before, &after).expect("gate");
    match verdict {
        GateVerdict::Reject { added, dlq_seq, .. } => {
            assert_eq!(added, vec![(1, "cap.b".into())]);
            let dlq = journal.get(dlq_seq).expect("dlq");
            assert_eq!(dlq.kind, EventKind::DlqEntry);
            assert!(dlq.taint.contains(TaintFlags::DLQ));
            assert_eq!(dlq.causality, vec![update_seq]);
        }
        GateVerdict::Allow => panic!("partial coverage must reject unauthorized part"),
    }
}

#[test]
fn repeated_grant_is_idempotent_for_gate() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    let before = CapabilityGraph::from_journal(&journal);

    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "fs.read");
    grant(&mut after_j, 16, 1, "fs.read"); // повторный грант
    let after = CapabilityGraph::from_journal(&after_j);

    assert!(!overgrant_diff(&before, &after).expanded);
    let update_seq = append(&mut journal, 16, 1, EventKind::CodeUpdate, encode_cap("update"));
    let len = journal.len();
    assert_eq!(
        gate_code_update(&mut journal, &key(0), EPOCH, 1, update_seq, &before, &after).expect("gate"),
        GateVerdict::Allow
    );
    assert_eq!(journal.len(), len);
}

#[test]
fn malformed_payload_is_ignored_by_graph() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    // Не CBOR text: мусор, CBOR uint, пустой payload.
    append(&mut journal, 16, 1, EventKind::CapGrant, vec![0xff, 0x00, 0x13]);
    append(&mut journal, 16, 1, EventKind::CapGrant, vec![0x18, 0x2a]);
    append(&mut journal, 16, 1, EventKind::CapGrant, Vec::new());
    // Отзыв мусорным payload тоже не должен снимать действующий грант.
    append(&mut journal, 16, 1, EventKind::CapRevoke, vec![0xff]);

    let graph = CapabilityGraph::from_journal(&journal);
    assert_eq!(graph.pairs(), vec![(1, "fs.read".into())]);
}

#[test]
fn replay_preserves_state_and_graph() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    let before = CapabilityGraph::from_journal(&journal);
    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "fs.read");
    grant(&mut after_j, 16, 1, "key.sign");
    let after = CapabilityGraph::from_journal(&after_j);
    let update_seq = append(&mut journal, 16, 1, EventKind::CodeUpdate, encode_cap("update"));
    gate_code_update(&mut journal, &key(0), EPOCH, 1, update_seq, &before, &after).expect("gate");

    let hash_before = journal.state_hash();
    let graph_before = CapabilityGraph::from_journal(&journal);
    journal.replay(0).expect("replay");
    assert_eq!(journal.state_hash(), hash_before);
    assert_eq!(CapabilityGraph::from_journal(&journal), graph_before);
}

#[test]
fn mutation_of_cap_record_detected_by_chain() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    grant(&mut journal, 16, 1, "net.fetch");
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("clean chain");

    let mut records: Vec<Record> = journal.iter().cloned().collect();
    records[0].payload[0] ^= 0x01; // подмена одного байта
    let tampered = Journal::from_records_unchecked(records, Cas::new());
    let err = tampered
        .verify_chain(0..tampered.len() as u64, &ROOT)
        .expect_err("mutation must be detected");
    assert!(matches!(err, VerifyError::MacMismatch { seq: 0 } | VerifyError::PrevHashMismatch { seq: 1 }));
}

#[test]
fn dlq_taint_inherited_by_child() {
    let mut journal = Journal::new();
    let before = CapabilityGraph::from_journal(&journal);
    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "key.sign");
    let after = CapabilityGraph::from_journal(&after_j);
    let update_seq = append(&mut journal, 16, 1, EventKind::CodeUpdate, encode_cap("update"));
    let dlq_seq = match gate_code_update(&mut journal, &key(0), EPOCH, 1, update_seq, &before, &after).expect("gate") {
        GateVerdict::Reject { dlq_seq, .. } => dlq_seq,
        GateVerdict::Allow => panic!("must reject"),
    };

    let child = Record::draft(
        EPOCH,
        16,
        journal.len() as u64,
        1,
        EventKind::AgentDecision,
        TaintFlags::empty(),
        vec![dlq_seq],
        encode_cap("decision"),
    );
    let child_seq = journal.append(child, &key(16)).expect("child");
    assert!(journal.get(child_seq).expect("child").taint.contains(TaintFlags::DLQ));
}

#[test]
fn dlq_inherits_tainted_update_at_gate_level() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    let upd = Record::draft(
        EPOCH, 16, journal.len() as u64, 1, EventKind::CodeUpdate,
        TaintFlags::EXTERNAL_NET, Vec::new(), encode_cap("update"),
    );
    let update_seq = journal.append(upd, &key(16)).expect("tainted update");
    let before = CapabilityGraph::from_journal(&journal);
    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "fs.read");
    grant(&mut after_j, 16, 1, "key.sign");
    let after = CapabilityGraph::from_journal(&after_j);

    let dlq_seq = match gate_code_update(&mut journal, &key(0), EPOCH, 1, update_seq, &before, &after).expect("gate") {
        GateVerdict::Reject { dlq_seq, .. } => dlq_seq,
        GateVerdict::Allow => panic!("overgrant must reject"),
    };
    let dlq = journal.get(dlq_seq).expect("dlq");
    assert_eq!(dlq.causality, vec![update_seq]);
    assert!(dlq.taint.contains(TaintFlags::DLQ));
    assert!(dlq.taint.contains(TaintFlags::EXTERNAL_NET));
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn gate_unknown_update_seq_fails_without_dlq() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    let before = CapabilityGraph::from_journal(&journal);
    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "fs.read");
    grant(&mut after_j, 16, 1, "key.sign");
    let after = CapabilityGraph::from_journal(&after_j);
    let len = journal.len();
    let hash = journal.state_hash();
    let result = gate_code_update(&mut journal, &key(0), EPOCH, 1, 999, &before, &after);
    assert_eq!(result, Err(AppendError::UnknownParent(999)));
    assert_eq!(journal.len(), len, "DLQ не записан при неизвестном update_seq");
    assert_eq!(journal.state_hash(), hash);
}

#[test]
fn surface_window_semantics() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "early.cap"); // seq 0: вне окна
    append(&mut journal, 16, 1, EventKind::McpRequest, encode_cap("win.cap")); // seq 1: использование до гранта
    grant(&mut journal, 16, 1, "win.cap"); // seq 2
    append(&mut journal, 16, 1, EventKind::McpRequest, encode_cap("win.cap")); // seq 3: использование в окне

    // Окно [2, 4): грант win.cap + его использование; early.cap не входит.
    let report = overgrant_surface(&journal, 2..4).expect("surface");
    assert_eq!(report.granted, 1);
    assert_eq!(report.used, 1);
    assert!(report.unused.is_empty());

    // Окно [2, 3): грант без использования внутри окна.
    let report = overgrant_surface(&journal, 2..3).expect("surface");
    assert_eq!(report.used, 0);
    assert_eq!(report.unused, vec![(1, "win.cap".into())]);

    // Полный журнал: early.cap не использовался никогда.
    let report = overgrant_surface(&journal, 0..4).expect("surface");
    assert_eq!(report.granted, 2);
    assert_eq!(report.used, 1);
    assert_eq!(report.unused, vec![(1, "early.cap".into())]);
}

#[test]
fn deterministic_reports_across_identical_journals() {
    let build = || {
        let mut j = Journal::new();
        grant(&mut j, 16, 5, "b.cap");
        grant(&mut j, 16, 2, "a.cap");
        append(&mut j, 16, 2, EventKind::McpRequest, encode_cap("a.cap"));
        j
    };
    let j1 = build();
    let j2 = build();
    assert_eq!(
        overgrant_surface(&j1, 0..j1.len() as u64).expect("s1"),
        overgrant_surface(&j2, 0..j2.len() as u64).expect("s2")
    );
    assert_eq!(CapabilityGraph::from_journal(&j1).pairs(), CapabilityGraph::from_journal(&j2).pairs());
}

#[test]
fn non_canonical_human_grant_does_not_authorize() {
    let mut journal = Journal::new();
    grant(&mut journal, 16, 1, "fs.read");
    let before = CapabilityGraph::from_journal(&journal);

    // Human-grant (домен 0) в неканонической длинной форме CBOR text:
    // не должен ни авторизовать расширение, ни пройти незаметно.
    let mut after_j = Journal::new();
    grant(&mut after_j, 16, 1, "fs.read");
    let mut long_form = vec![0x78, 0x08];
    long_form.extend_from_slice(b"key.sign");
    let bad_seq = append(&mut after_j, 0, 1, EventKind::CapGrant, long_form);
    let after = CapabilityGraph::from_journal(&after_j);

    let update_seq = append(&mut journal, 16, 1, EventKind::CodeUpdate, encode_cap("update"));
    let verdict = gate_code_update(&mut journal, &key(0), EPOCH, 1, update_seq, &before, &after).expect("gate");
    match verdict {
        GateVerdict::Reject { malformed, dlq_seq, .. } => {
            assert_eq!(malformed, vec![bad_seq]);
            assert!(journal.get(dlq_seq).expect("dlq").taint.contains(TaintFlags::DLQ));
        }
        GateVerdict::Allow => panic!("non-canonical human-grant must fail closed"),
    }
}