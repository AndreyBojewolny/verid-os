//! Тесты reachability v0 (TASK-003): граф, overgrant_diff, гейт + DLQ, surface.

use veridos_journal::journal::{EventKind, Journal, Record, TaintFlags};
use veridos_journal::reachability::{
    gate_code_update, overgrant_diff, overgrant_surface, CapabilityGraph, GateVerdict, SurfaceError,
};
use veridos_journal::reachability::graph::encode_cap;

const KEY: [u8; 32] = [7u8; 32];
const EPOCH: u32 = 1;
const CELL: u64 = 42;

fn append(journal: &mut Journal, domain: u8, actor: u64, kind: EventKind, cap: &str) -> u64 {
    let rec = Record::draft(
        EPOCH,
        domain,
        journal.len() as u64,
        actor,
        kind,
        TaintFlags::empty(),
        Vec::new(),
        encode_cap(cap),
    );
    journal.append(rec, &KEY).expect("append")
}

fn journal_with_grants() -> Journal {
    let mut journal = Journal::new();
    append(&mut journal, 16, CELL, EventKind::CapGrant, "fs.read");
    append(&mut journal, 16, CELL, EventKind::CapGrant, "net.fetch");
    journal
}

#[test]
fn graph_reflects_grants_and_revokes() {
    let mut journal = journal_with_grants();
    append(&mut journal, 16, CELL, EventKind::CapRevoke, "net.fetch");

    let graph = CapabilityGraph::from_journal(&journal);
    let caps = graph.capabilities(CELL);
    assert!(caps.contains("fs.read"));
    assert!(!caps.contains("net.fetch"));
    assert!(graph.capabilities(999).is_empty());
}

#[test]
fn diff_detects_expansion() {
    let before = CapabilityGraph::from_journal(&journal_with_grants());
    let mut after_journal = journal_with_grants();
    append(&mut after_journal, 16, CELL, EventKind::CapGrant, "key.sign");
    let after = CapabilityGraph::from_journal(&after_journal);

    let diff = overgrant_diff(&before, &after);
    assert!(diff.expanded);
    assert_eq!(diff.added, vec![(CELL, "key.sign".into())]);
}

#[test]
fn diff_reduction_passes() {
    let before = CapabilityGraph::from_journal(&journal_with_grants());
    let mut after_journal = journal_with_grants();
    append(&mut after_journal, 16, CELL, EventKind::CapRevoke, "net.fetch");
    let after = CapabilityGraph::from_journal(&after_journal);

    let diff = overgrant_diff(&before, &after);
    assert!(!diff.expanded);
    assert!(diff.added.is_empty());
}

#[test]
fn gate_rejects_expansion_and_writes_dlq() {
    let mut journal = journal_with_grants();
    let before = CapabilityGraph::from_journal(&journal);
    let mut after_journal = journal_with_grants();
    append(&mut after_journal, 16, CELL, EventKind::CapGrant, "key.sign");
    let after = CapabilityGraph::from_journal(&after_journal);

    let update_seq = append(&mut journal, 16, CELL, EventKind::CodeUpdate, "update");
    let len_before = journal.len();
    let verdict = gate_code_update(&mut journal, &KEY, EPOCH, CELL, update_seq, &before, &after).expect("gate");
    match verdict {
        GateVerdict::Reject { added, dlq_seq, .. } => {
            assert_eq!(added, vec![(CELL, "key.sign".into())]);
            assert_eq!(dlq_seq, len_before as u64);
        }
        GateVerdict::Allow => panic!("expansion must be rejected"),
    }
    assert_eq!(journal.len(), len_before + 1);
    let dlq = journal.get(journal.len() as u64 - 1).expect("dlq record");
    assert_eq!(dlq.kind, EventKind::DlqEntry);
    assert!(dlq.taint.contains(TaintFlags::DLQ));
    assert_eq!(dlq.causality, vec![update_seq]);
}

#[test]
fn gate_allows_human_granted_expansion() {
    let mut journal = journal_with_grants();
    let before = CapabilityGraph::from_journal(&journal);
    let mut after_journal = journal_with_grants();
    // Явный human-grant: CapGrant в домене 0 (L0, владелец).
    append(&mut after_journal, 0, CELL, EventKind::CapGrant, "key.sign");
    let after = CapabilityGraph::from_journal(&after_journal);

    let update_seq = append(&mut journal, 16, CELL, EventKind::CodeUpdate, "update");
    let len_before = journal.len();
    let verdict = gate_code_update(&mut journal, &KEY, EPOCH, CELL, update_seq, &before, &after).expect("gate");
    assert_eq!(verdict, GateVerdict::Allow);
    assert_eq!(journal.len(), len_before);
}

#[test]
fn gate_allows_reduction_without_records() {
    let mut journal = journal_with_grants();
    let before = CapabilityGraph::from_journal(&journal);
    let mut after_journal = journal_with_grants();
    append(&mut after_journal, 16, CELL, EventKind::CapRevoke, "net.fetch");
    let after = CapabilityGraph::from_journal(&after_journal);

    let update_seq = append(&mut journal, 16, CELL, EventKind::CodeUpdate, "update");
    let len_before = journal.len();
    let verdict = gate_code_update(&mut journal, &KEY, EPOCH, CELL, update_seq, &before, &after).expect("gate");
    assert_eq!(verdict, GateVerdict::Allow);
    assert_eq!(journal.len(), len_before);
}

#[test]
fn revoked_human_grant_does_not_authorize_reexpansion() {
    let mut journal = Journal::new();
    append(&mut journal, 0, CELL, EventKind::CapGrant, "key.sign");
    append(&mut journal, 0, CELL, EventKind::CapRevoke, "key.sign");
    let before = CapabilityGraph::from_journal(&journal);

    let mut after_journal = Journal::new();
    append(&mut after_journal, 0, CELL, EventKind::CapGrant, "key.sign");
    append(&mut after_journal, 0, CELL, EventKind::CapRevoke, "key.sign");
    append(&mut after_journal, 16, CELL, EventKind::CapGrant, "key.sign");
    let after = CapabilityGraph::from_journal(&after_journal);

    let update_seq = append(&mut journal, 16, CELL, EventKind::CodeUpdate, "update");
    let verdict = gate_code_update(&mut journal, &KEY, EPOCH, CELL, update_seq, &before, &after).expect("gate");
    assert!(matches!(verdict, GateVerdict::Reject { .. }));
}

#[test]
fn surface_reports_unused_capabilities() {
    let mut journal = journal_with_grants();
    append(&mut journal, 16, CELL, EventKind::McpRequest, "fs.read");

    let report = overgrant_surface(&journal, 0..journal.len() as u64).expect("surface");
    assert_eq!(report.granted, 2);
    assert_eq!(report.used, 1);
    assert_eq!(report.unused, vec![(CELL, "net.fetch".into())]);

    // Детерминированность: повторный расчёт даёт идентичный отчёт.
    let again = overgrant_surface(&journal, 0..journal.len() as u64).expect("surface");
    assert_eq!(report, again);
}

#[test]
fn surface_window_bounds_checked() {
    let journal = journal_with_grants();
    assert_eq!(
        overgrant_surface(&journal, 0..journal.len() as u64 + 1),
        Err(SurfaceError::OutOfRange)
    );
    let (start, end) = (2u64, 1u64);
    assert_eq!(overgrant_surface(&journal, start..end), Err(SurfaceError::OutOfRange));
}

#[test]
fn non_canonical_payload_is_malformed() {
    use veridos_journal::reachability::decode_cap;
    // "fs.read" в длинной форме CBOR text (0x78 0x07) — не канон.
    let mut long_form = vec![0x78, 0x07];
    long_form.extend_from_slice(b"fs.read");
    assert_eq!(decode_cap(&long_form), None);
    assert_eq!(decode_cap(&encode_cap("fs.read")), Some("fs.read".into()));

    let mut journal = Journal::new();
    let rec = Record::draft(
        EPOCH, 16, 0, CELL, EventKind::CapGrant, TaintFlags::empty(), Vec::new(), long_form,
    );
    let seq = journal.append(rec, &KEY).expect("append");
    let graph = CapabilityGraph::from_journal(&journal);
    assert!(graph.capabilities(CELL).is_empty());
    assert_eq!(graph.malformed_events(), &[seq]);
}

#[test]
fn malformed_event_in_after_fails_closed() {
    let mut journal = journal_with_grants();
    let before = CapabilityGraph::from_journal(&journal);

    let mut after_journal = journal_with_grants();
    let rec = Record::draft(
        EPOCH, 16, after_journal.len() as u64, CELL, EventKind::CapGrant,
        TaintFlags::empty(), Vec::new(), vec![0xff],
    );
    let bad_seq = after_journal.append(rec, &KEY).expect("append");
    let after = CapabilityGraph::from_journal(&after_journal);

    // Расширения в графе нет, но malformed-грант невидим -> fail-closed.
    assert!(!overgrant_diff(&before, &after).expanded);
    let update_seq = append(&mut journal, 16, CELL, EventKind::CodeUpdate, "update");
    let verdict = gate_code_update(&mut journal, &KEY, EPOCH, CELL, update_seq, &before, &after).expect("gate");
    match verdict {
        GateVerdict::Reject { added, malformed, dlq_seq } => {
            assert!(added.is_empty());
            assert_eq!(malformed, vec![bad_seq]);
            assert!(journal.get(dlq_seq).expect("dlq").taint.contains(TaintFlags::DLQ));
        }
        GateVerdict::Allow => panic!("malformed grant must fail closed"),
    }
}

#[test]
fn malformed_event_in_before_fails_closed() {
    let mut journal = Journal::new();
    append(&mut journal, 16, CELL, EventKind::CapGrant, "fs.read");
    let rec = Record::draft(
        EPOCH, 16, journal.len() as u64, CELL, EventKind::CapRevoke,
        TaintFlags::empty(), Vec::new(), vec![0xff],
    );
    let bad_seq = journal.append(rec, &KEY).expect("append");
    let before = CapabilityGraph::from_journal(&journal);
    let after = before.clone();

    let update_seq = append(&mut journal, 16, CELL, EventKind::CodeUpdate, "update");
    let verdict = gate_code_update(&mut journal, &KEY, EPOCH, CELL, update_seq, &before, &after).expect("gate");
    match verdict {
        GateVerdict::Reject { malformed, .. } => assert_eq!(malformed, vec![bad_seq]),
        GateVerdict::Allow => panic!("malformed revoke in before must fail closed"),
    }
}