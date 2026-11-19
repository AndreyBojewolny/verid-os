//! Gate-тесты ядра журнала (TASK-005): мутационный, replay/state_hash,
//! идемпотентность, taint-OR, канонический CBOR, CAS, sink, закрытые словари.

use std::sync::{Arc, Mutex};

use veridos_journal::journal::cas::{Cas, THRESHOLD};
use veridos_journal::journal::cbor::{self, CborError};
use veridos_journal::journal::mac;
use veridos_journal::journal::{
    AppendError, EventKind, Journal, Record, ReplayError, TaintFlags, VerifyError, WarnSink,
};

const ROOT: [u8; 32] = [7u8; 32];

fn mk(epoch: u32, domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, epoch), domain)
}

fn draft(kind: EventKind, source_seq: u64, payload: Vec<u8>) -> Record {
    Record::draft(0, 0, source_seq, 0, kind, TaintFlags::empty(), Vec::new(), payload)
}

#[derive(Clone, Default)]
struct CollectSink(Arc<Mutex<Vec<String>>>);

impl WarnSink for CollectSink {
    fn warn(&mut self, message: &str) {
        self.0.lock().unwrap().push(message.to_string());
    }
}

fn sample_journal() -> Journal {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    journal
        .append(draft(EventKind::TaskStart, 0, b"hello".to_vec()), &key)
        .unwrap();
    let mut second = draft(EventKind::AgentDecision, 1, vec![1, 2, 3]);
    second.causality = vec![0];
    second.taint = TaintFlags::LLM_OUTPUT;
    journal.append(second, &key).unwrap();
    journal
        .append(draft(EventKind::TaskEnd, 2, Vec::new()), &key)
        .unwrap();
    journal
}

#[test]
fn append_assigns_seq_and_builds_chain() {
    let journal = sample_journal();
    assert_eq!(journal.len(), 3);
    for (i, rec) in journal.iter().enumerate() {
        assert_eq!(rec.seq, i as u64);
    }
    assert_eq!(journal.get(0).unwrap().prev_hash, [0; 32]);
    for i in 1..journal.len() {
        let prev = journal.get(i as u64 - 1).unwrap();
        let expected = *blake3::hash(&cbor::encode(&prev)).as_bytes();
        assert_eq!(journal.get(i as u64).unwrap().prev_hash, expected);
    }
    assert!(journal.get(99).is_none());
    assert_eq!(journal.iter().count(), 3);
    assert!(journal.verify_chain(0..3, &ROOT).is_ok());
}

#[test]
fn verify_chain_rejects_wrong_root_key() {
    let journal = sample_journal();
    let wrong_root = [8u8; 32];
    assert_eq!(
        journal.verify_chain(0..3, &wrong_root),
        Err(VerifyError::MacMismatch { seq: 0 })
    );
    assert_eq!(journal.verify_chain(0..4, &ROOT), Err(VerifyError::OutOfRange));
}

#[test]
fn mutation_of_any_single_byte_is_detected() {
    let journal = sample_journal();
    let records: Vec<Record> = journal.iter().cloned().collect();
    let mut checked = 0usize;
    for i in 0..records.len() {
        let bytes = cbor::encode(&records[i]);
        for j in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[j] ^= 0x01;
            match cbor::decode(&mutated) {
                Err(_) => {
                    // Подмена обнаружена уже на этапе разбора канонического CBOR.
                }
                Ok(mutated_rec) => {
                    let mut tampered = records.clone();
                    tampered[i] = mutated_rec;
                    let rebuilt = Journal::from_records_unchecked(tampered, Cas::new());
                    assert!(
                        rebuilt.verify_chain(0..3, &ROOT).is_err(),
                        "мутация байта {} записи {} не обнаружена",
                        j,
                        i
                    );
                }
            }
            checked += 1;
        }
    }
    assert!(checked > 0);
}

#[test]
fn replay_restores_state_hash() {
    let mut journal = sample_journal();
    let key = mk(0, 0);
    let mut validate = draft(EventKind::Validate, 3, Vec::new());
    validate.causality = vec![1];
    journal.append(validate, &key).unwrap();

    let before_checkpoint = journal.state_hash();
    let checkpoint = journal.checkpoint(0, &key).unwrap();
    assert_eq!(checkpoint.kind, EventKind::Checkpoint);
    assert_eq!(checkpoint.payload, before_checkpoint.to_vec());

    let full_hash = journal.state_hash();
    journal.replay(0).unwrap();
    assert_eq!(journal.state_hash(), full_hash);

    journal.replay(journal.len() as u64).unwrap();
    assert_eq!(journal.state_hash(), Journal::new().state_hash());
    assert_eq!(journal.replay(99), Err(ReplayError::OutOfRange));
}

#[test]
fn taint_inherits_by_or_along_chain() {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    let mut parent = draft(EventKind::McpResponse, 0, Vec::new());
    parent.taint = TaintFlags::EXTERNAL_NET;
    let p = journal.append(parent, &key).unwrap();

    let mut child = draft(EventKind::AgentDecision, 1, Vec::new());
    child.causality = vec![p];
    child.taint = TaintFlags::LLM_OUTPUT;
    let c = journal.append(child, &key).unwrap();
    assert_eq!(
        journal.get(c).unwrap().taint,
        TaintFlags::EXTERNAL_NET | TaintFlags::LLM_OUTPUT
    );

    let mut grandchild = draft(EventKind::TaskEnd, 2, Vec::new());
    grandchild.causality = vec![c];
    let g = journal.append(grandchild, &key).unwrap();
    assert_eq!(
        journal.get(g).unwrap().taint,
        TaintFlags::EXTERNAL_NET | TaintFlags::LLM_OUTPUT
    );

    let mut multi = draft(EventKind::McpRequest, 3, Vec::new());
    multi.causality = vec![p, g];
    multi.taint = TaintFlags::UNVALIDATED;
    let m = journal.append(multi, &key).unwrap();
    assert_eq!(
        journal.get(m).unwrap().taint,
        TaintFlags::EXTERNAL_NET | TaintFlags::LLM_OUTPUT | TaintFlags::UNVALIDATED
    );
}

#[test]
fn validate_clears_unvalidated_only_via_journal_operation() {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    let mut parent = draft(EventKind::McpResponse, 0, Vec::new());
    parent.taint = TaintFlags::UNVALIDATED | TaintFlags::LLM_OUTPUT;
    let p = journal.append(parent, &key).unwrap();
    assert!(journal.get(p).unwrap().taint.contains(TaintFlags::UNVALIDATED));

    let mut validate = draft(EventKind::Validate, 1, Vec::new());
    validate.causality = vec![p];
    let v = journal.append(validate, &key).unwrap();
    let taint = journal.get(v).unwrap().taint;
    assert!(!taint.contains(TaintFlags::UNVALIDATED));
    assert!(taint.contains(TaintFlags::VALIDATED));
    assert!(taint.contains(TaintFlags::LLM_OUTPUT));

    let hash_after = journal.state_hash();
    journal.replay(0).unwrap();
    assert_eq!(journal.state_hash(), hash_after);
}

#[test]
fn redelivery_is_idempotent() {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    let event = draft(EventKind::McpRequest, 42, b"same-event".to_vec());
    let first = journal.append(event.clone(), &key).unwrap();
    let hash_after_first = journal.state_hash();
    let second = journal.append(event, &key).unwrap();
    assert_eq!(first, second);
    assert_eq!(journal.len(), 1);
    assert_eq!(journal.state_hash(), hash_after_first);
    assert!(journal.verify_chain(0..1, &ROOT).is_ok());
}

#[test]
fn cbor_is_canonical_fixed_vector() {
    let mut rec = Record::draft(0, 0, 0, 0, EventKind::TaskStart, TaintFlags::empty(), Vec::new(), Vec::new());
    rec.seq = 1;

    let mut expected: Vec<u8> = vec![0xAB];
    expected.extend_from_slice(&[0x63, b'm', b'a', b'c', 0x50]);
    expected.extend_from_slice(&[0u8; 16]);
    expected.extend_from_slice(&[0x63, b's', b'e', b'q', 0x01]);
    expected.extend_from_slice(&[0x64, b'k', b'i', b'n', b'd', 0x0C]);
    expected.extend_from_slice(&[0x65, b'a', b'c', b't', b'o', b'r', 0x00]);
    expected.extend_from_slice(&[0x65, b'e', b'p', b'o', b'c', b'h', 0x00]);
    expected.extend_from_slice(&[0x65, b't', b'a', b'i', b'n', b't', 0x00]);
    expected.extend_from_slice(&[0x66, b'd', b'o', b'm', b'a', b'i', b'n', 0x00]);
    expected.extend_from_slice(&[0x67, b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x40]);
    expected.extend_from_slice(&[0x69, b'c', b'a', b'u', b's', b'a', b'l', b'i', b't', b'y', 0x80]);
    expected.extend_from_slice(&[0x69, b'p', b'r', b'e', b'v', b'_', b'h', b'a', b's', b'h', 0x58, 0x20]);
    expected.extend_from_slice(&[0u8; 32]);
    expected.extend_from_slice(&[0x6A, b's', b'o', b'u', b'r', b'c', b'e', b'_', b's', b'e', b'q', 0x00]);

    let encoded = cbor::encode(&rec);
    assert_eq!(encoded, expected);
    assert_eq!(cbor::encode(&rec), encoded);
    assert_eq!(cbor::decode(&encoded).unwrap(), rec);
}

#[test]
fn cbor_roundtrip_rich_record_and_rejects_garbage() {
    let mut rec = Record::draft(
        3,
        16,
        u64::MAX,
        123456789,
        EventKind::CellHalt,
        TaintFlags::EXTERNAL_NET | TaintFlags::REPLAYED,
        vec![0, 5, u64::MAX],
        (0..300u32).map(|v| v as u8).collect(),
    );
    rec.seq = 42;
    rec.prev_hash = [0xAA; 32];
    rec.mac = [0xBB; 16];
    let encoded = cbor::encode(&rec);
    assert_eq!(cbor::decode(&encoded).unwrap(), rec);

    assert!(cbor::decode(&[]).is_err());
    assert!(cbor::decode(&[0xFF]).is_err());
    assert_eq!(cbor::decode(&[0xA0]), Err(CborError::Shape));
}

#[test]
fn cas_threshold_boundaries() {
    let mut journal = Journal::new();
    let key = mk(0, 0);

    journal.append(draft(EventKind::TaskStart, 0, Vec::new()), &key).unwrap();
    assert_eq!(journal.get(0).unwrap().payload.len(), 0);
    assert!(journal.cas().is_empty());

    let inline = vec![0x5Au8; THRESHOLD];
    journal.append(draft(EventKind::McpRequest, 1, inline.clone()), &key).unwrap();
    assert_eq!(journal.get(1).unwrap().payload, inline);
    assert!(journal.cas().is_empty());

    let big = vec![0xA5u8; THRESHOLD + 1];
    journal.append(draft(EventKind::McpResponse, 2, big.clone()), &key).unwrap();
    let stored = journal.get(2).unwrap();
    assert_eq!(stored.payload.len(), 32);
    let hash: [u8; 32] = stored.payload.clone().try_into().unwrap();
    assert_eq!(hash, *blake3::hash(&big).as_bytes());
    assert_eq!(journal.cas().get(&hash).unwrap(), big.as_slice());
    assert_eq!(journal.cas().len(), 1);
    assert!(journal.verify_chain(0..3, &ROOT).is_ok());
}

#[test]
fn sink_receives_warnings_and_replayed_is_silent() {
    let mut journal = Journal::new();
    let sink = CollectSink::default();
    journal.set_sink(Box::new(sink.clone()));
    let key = mk(0, 0);

    let mut tainted = draft(EventKind::McpResponse, 0, Vec::new());
    tainted.taint = TaintFlags::LLM_OUTPUT;
    journal.append(tainted, &key).unwrap();
    assert_eq!(sink.0.lock().unwrap().len(), 1);

    let mut replayed = draft(EventKind::ReplayEvent, 1, Vec::new());
    replayed.taint = TaintFlags::REPLAYED | TaintFlags::LLM_OUTPUT;
    journal.append(replayed, &key).unwrap();
    assert_eq!(sink.0.lock().unwrap().len(), 1);

    journal.replay(0).unwrap();
    assert_eq!(sink.0.lock().unwrap().len(), 1);

    journal.append(draft(EventKind::TaskEnd, 2, Vec::new()), &key).unwrap();
    assert_eq!(sink.0.lock().unwrap().len(), 1);
}

#[test]
fn event_kind_dictionary_is_closed() {
    for code in 0..=15u8 {
        let kind = EventKind::from_u8(code).unwrap();
        assert_eq!(kind.as_u8(), code);
    }
    for code in 16..=255u8 {
        assert!(EventKind::from_u8(code).is_none());
    }
    assert!(TaintFlags::from_bits(1 << 9).is_none());
}

#[test]
fn key_derivation_is_deterministic_and_separated() {
    let e0 = mac::epoch_key(&ROOT, 0);
    let e1 = mac::epoch_key(&ROOT, 1);
    assert_eq!(e0, mac::epoch_key(&ROOT, 0));
    assert_ne!(e0, e1);
    let m00 = mac::mac_key(&e0, 0);
    let m01 = mac::mac_key(&e0, 1);
    let m10 = mac::mac_key(&e1, 0);
    assert_eq!(m00, mac::mac_key(&e0, 0));
    assert_ne!(m00, m01);
    assert_ne!(m00, m10);

    let data = b"record-bytes";
    let tag = mac::compute_mac(&m00, data);
    assert!(mac::verify_mac(&m00, data, &tag));
    assert!(!mac::verify_mac(&m01, data, &tag));
    let mut bad = tag;
    bad[0] ^= 1;
    assert!(!mac::verify_mac(&m00, data, &bad));
}

#[test]
fn verify_chain_uses_per_record_epoch_keys() {
    let mut journal = Journal::new();
    journal
        .append(draft(EventKind::TaskStart, 0, Vec::new()), &mk(0, 0))
        .unwrap();
    let mut rotated = draft(EventKind::EpochRotate, 1, Vec::new());
    rotated.epoch = 1;
    journal.append(rotated, &mk(1, 0)).unwrap();
    let mut after = draft(EventKind::TaskEnd, 2, Vec::new());
    after.epoch = 1;
    after.domain = 16;
    journal.append(after, &mk(1, 16)).unwrap();
    assert!(journal.verify_chain(0..3, &ROOT).is_ok());
    assert!(journal.verify_chain(1..3, &ROOT).is_ok());
}

#[test]
fn unknown_parent_is_rejected_without_side_effects() {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    let mut orphan = draft(EventKind::AgentDecision, 0, Vec::new());
    orphan.causality = vec![99];
    let hash_before = journal.state_hash();
    assert_eq!(journal.append(orphan, &key), Err(AppendError::UnknownParent(99)));
    assert!(journal.is_empty());
    assert_eq!(journal.state_hash(), hash_before);
}