//! Независимые проверки VERIFIER для TASK-005 (адверсариальные сценарии,
//! каноничность CBOR на границах целых, детерминизм state_hash).
//! Код src/ не изменяется — только тесты.

use veridos_journal::journal::cas::Cas;
use veridos_journal::journal::cbor;
use veridos_journal::journal::mac;
use veridos_journal::journal::{AppendError, EventKind, Journal, Record, TaintFlags, VerifyError};

const ROOT: [u8; 32] = [7u8; 32];

fn mk(epoch: u32, domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, epoch), domain)
}

fn draft(kind: EventKind, source_seq: u64, payload: Vec<u8>) -> Record {
    Record::draft(0, 0, source_seq, 0, kind, TaintFlags::empty(), Vec::new(), payload)
}

fn verifier_sample() -> Journal {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    journal.append(draft(EventKind::TaskStart, 0, b"hello".to_vec()), &key).unwrap();
    let mut second = draft(EventKind::AgentDecision, 1, vec![1, 2, 3]);
    second.causality = vec![0];
    second.taint = TaintFlags::LLM_OUTPUT;
    journal.append(second, &key).unwrap();
    journal.append(draft(EventKind::TaskEnd, 2, Vec::new()), &key).unwrap();
    // Получатель (actor 7) потребляет запись 1, затем валидирует её.
    let consumer = Record::draft(0, 0, 3, 7, EventKind::AgentDecision, TaintFlags::empty(), vec![1], Vec::new());
    journal.append(consumer, &key).unwrap();
    let validate = Record::draft(0, 0, 4, 7, EventKind::Validate, TaintFlags::empty(), vec![1], Vec::new());
    journal.append(validate, &key).unwrap();
    journal
}

#[test]
fn cbor_uint_encoding_is_canonical_at_boundaries() {
    // Кодировка source_seq — последний элемент канонического map;
    // проверяем кратчайшую форму целых на всех границах CBOR.
    let cases: Vec<(u64, Vec<u8>)> = vec![
        (0, vec![0x00]),
        (23, vec![0x17]),
        (24, vec![0x18, 0x18]),
        (255, vec![0x18, 0xFF]),
        (256, vec![0x19, 0x01, 0x00]),
        (65535, vec![0x19, 0xFF, 0xFF]),
        (65536, vec![0x1A, 0x00, 0x01, 0x00, 0x00]),
        (4294967295, vec![0x1A, 0xFF, 0xFF, 0xFF, 0xFF]),
        (4294967296, vec![0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
        (u64::MAX, vec![0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    ];
    let mut key_bytes = vec![0x6Au8];
    key_bytes.extend_from_slice(b"source_seq");
    for (value, expected_uint) in cases {
        let mut rec = draft(EventKind::TaskStart, value, Vec::new());
        rec.seq = 0;
        let encoded = cbor::encode(&rec);
        assert_eq!(encoded[0], 0xAB, "map из 11 полей");
        let mut expected_tail = key_bytes.clone();
        expected_tail.extend_from_slice(&expected_uint);
        assert!(
            encoded.ends_with(&expected_tail),
            "source_seq={value}: неверная каноническая кодировка"
        );
        assert_eq!(cbor::decode(&encoded).unwrap().source_seq, value);
    }
}

#[test]
fn reorder_attack_is_detected() {
    let journal = verifier_sample();
    let mut records: Vec<Record> = journal.iter().cloned().collect();
    records.swap(1, 2);
    let rebuilt = Journal::from_records_unchecked(records, Cas::new());
    assert!(rebuilt.verify_chain(0..5, &ROOT).is_err());
}

#[test]
fn truncation_is_detected_by_range_and_replay_diverges() {
    let journal = verifier_sample();
    let full_hash = journal.state_hash();
    let anchor = journal.anchor();
    let mut records: Vec<Record> = journal.iter().cloned().collect();
    records.pop();
    let truncated = Journal::from_records_unchecked(records, Cas::new());
    assert_eq!(truncated.verify_chain(0..5, &ROOT), Err(VerifyError::OutOfRange));
    assert!(truncated.verify_chain(0..4, &ROOT).is_ok());
    assert_ne!(truncated.state_hash(), full_hash);
    assert_eq!(truncated.verify_anchor(&anchor), Err(VerifyError::AnchorMismatch));
}

#[test]
fn append_with_wrong_domain_key_fails_verification() {
    let mut journal = Journal::new();
    // Запись домена 0 подписана ключом домена 1.
    journal.append(draft(EventKind::TaskStart, 0, Vec::new()), &mk(0, 1)).unwrap();
    assert_eq!(
        journal.verify_chain(0..1, &ROOT),
        Err(VerifyError::MacMismatch { seq: 0 })
    );
}

#[test]
fn mac_byte_mutations_are_detected_directly() {
    let journal = verifier_sample();
    let records: Vec<Record> = journal.iter().cloned().collect();
    for i in 0..records.len() {
        for byte in 0..16 {
            let mut tampered = records.clone();
            tampered[i].mac[byte] ^= 0x80;
            let rebuilt = Journal::from_records_unchecked(tampered, Cas::new());
            assert!(
                rebuilt.verify_chain(0..5, &ROOT).is_err(),
                "мутация mac[{}] записи {} не обнаружена",
                byte,
                i
            );
        }
    }
}

#[test]
fn rebuild_and_replay_are_deterministic() {
    let journal = verifier_sample();
    let original_hash = journal.state_hash();
    let records: Vec<Record> = journal.iter().cloned().collect();
    let mut rebuilt = Journal::from_records_unchecked(records, Cas::new());
    assert_eq!(rebuilt.state_hash(), original_hash);
    rebuilt.replay(0).unwrap();
    assert_eq!(rebuilt.state_hash(), original_hash);
    assert!(rebuilt.verify_chain(0..5, &ROOT).is_ok());

    let mut second = verifier_sample();
    second.replay(0).unwrap();
    assert_eq!(second.state_hash(), original_hash);
}

#[test]
fn checkpoints_are_unique_and_chain_stays_valid() {
    let mut journal = verifier_sample();
    let key = mk(0, 0);
    let first = journal.checkpoint(0, &key).unwrap();
    let second = journal.checkpoint(0, &key).unwrap();
    assert_ne!(first.seq, second.seq);
    assert_ne!(first.payload, second.payload);
    assert!(journal.verify_chain(0..journal.len() as u64, &ROOT).is_ok());
    let hash = journal.state_hash();
    journal.replay(0).unwrap();
    assert_eq!(journal.state_hash(), hash);
}

#[test]
fn redelivery_with_changed_causality_dedups_by_identity_key() {
    // Документирование семантики: ключ идентичности не включает causality/taint/epoch.
    let mut journal = Journal::new();
    let key = mk(0, 0);
    journal.append(draft(EventKind::TaskStart, 0, Vec::new()), &key).unwrap();
    let mut parent = draft(EventKind::McpResponse, 1, Vec::new());
    parent.taint = TaintFlags::EXTERNAL_NET;
    journal.append(parent, &key).unwrap();

    let mut redelivered = draft(EventKind::TaskStart, 0, Vec::new());
    redelivered.causality = vec![1];
    redelivered.taint = TaintFlags::LLM_OUTPUT;
    let seq = journal.append(redelivered, &key).unwrap();
    assert_eq!(seq, 0);
    assert_eq!(journal.len(), 2);
    assert_eq!(journal.get(0).unwrap().causality, Vec::<u64>::new());
}

#[test]
fn empty_journal_operations_are_safe() {
    let mut journal = Journal::new();
    assert!(journal.verify_chain(0..0, &ROOT).is_ok());
    assert!(journal.replay(0).is_ok());
    assert!(journal.get(0).is_none());
    assert_eq!(journal.iter().count(), 0);
}

#[test]
fn state_hash_reproducibility_anchor() {
    // Фиксированный сценарий для отчёта VERIFIER: hex печатается с --nocapture.
    let mut journal = verifier_sample();
    let key = mk(0, 0);
    journal.checkpoint(0, &key).unwrap();
    let hash = journal.state_hash();
    journal.replay(0).unwrap();
    assert_eq!(journal.state_hash(), hash);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    println!("VERIFIER state_hash anchor (6 записей incl. checkpoint): {hex}");
}

#[test]
fn service_flags_cannot_be_claimed_by_source() {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    let mut claimed = draft(EventKind::McpResponse, 0, Vec::new());
    claimed.taint = TaintFlags::VALIDATED | TaintFlags::REPLAYED;
    let seq = journal.append(claimed, &key).unwrap();
    assert_eq!(journal.get(seq).unwrap().taint, TaintFlags::empty());

    // Наследование служебных флагов от родителей сохраняется.
    let mut replayed = draft(EventKind::ReplayEvent, 1, Vec::new());
    replayed.taint = TaintFlags::LLM_OUTPUT;
    let r = journal.append_replayed(replayed, &key).unwrap();
    let mut child = draft(EventKind::AgentDecision, 2, Vec::new());
    child.causality = vec![r];
    let c = journal.append(child, &key).unwrap();
    assert!(journal.get(c).unwrap().taint.contains(TaintFlags::REPLAYED));
}

#[test]
fn validate_requires_prior_consumption_by_same_actor() {
    let mut journal = Journal::new();
    let key = mk(0, 0);
    let mut parent = draft(EventKind::McpResponse, 0, Vec::new());
    parent.taint = TaintFlags::UNVALIDATED;
    let p = journal.append(parent, &key).unwrap();

    let stranger = Record::draft(0, 0, 1, 9, EventKind::Validate, TaintFlags::empty(), vec![p], Vec::new());
    assert_eq!(journal.append(stranger, &key), Err(AppendError::NotRecipient(p)));

    // Потребление другим актором не авторизует Validate актора 9.
    let other_consumer = Record::draft(0, 0, 2, 5, EventKind::AgentDecision, TaintFlags::empty(), vec![p], Vec::new());
    journal.append(other_consumer, &key).unwrap();
    let stranger = Record::draft(0, 0, 3, 9, EventKind::Validate, TaintFlags::empty(), vec![p], Vec::new());
    assert_eq!(journal.append(stranger, &key), Err(AppendError::NotRecipient(p)));

    // Сам потребитель валидирует успешно; UNVALIDATED снят только у Validate-записи.
    let validator = Record::draft(0, 0, 4, 5, EventKind::Validate, TaintFlags::empty(), vec![p], Vec::new());
    let v = journal.append(validator, &key).unwrap();
    assert!(journal.get(v).unwrap().taint.contains(TaintFlags::VALIDATED));
    assert!(!journal.get(v).unwrap().taint.contains(TaintFlags::UNVALIDATED));
    assert!(journal.get(p).unwrap().taint.contains(TaintFlags::UNVALIDATED));
    assert!(journal.verify_chain(0..journal.len() as u64, &ROOT).is_ok());
}

#[test]
fn anchor_detects_reorder_and_divergent_state() {
    let journal = verifier_sample();
    let anchor = journal.anchor();
    assert!(journal.verify_anchor(&anchor).is_ok());

    let mut records: Vec<Record> = journal.iter().cloned().collect();
    records.swap(0, 1);
    let reordered = Journal::from_records_unchecked(records, Cas::new());
    assert_eq!(reordered.verify_anchor(&anchor), Err(VerifyError::AnchorMismatch));

    let mut different = verifier_sample();
    different.append(draft(EventKind::CellSpawn, 99, Vec::new()), &mk(0, 0)).unwrap();
    assert_eq!(different.verify_anchor(&anchor), Err(VerifyError::AnchorMismatch));
}