//! Независимая проверка VERIFIER для TASK-006 (diff-v2, CAS-вынос).
//! Собственный генератор сценария (независимая реализация по брифу) обязан
//! воспроизвести пинный хеш побитно; плюс адверсариальные углы: дедуп CAS
//! через эпохи/домены, граница порога на одиночных записях, replay с
//! checkpoint-границ, покрытие содержимого CAS цепочкой (ограничение v0).

use veridos_journal::journal::cas::{Cas, THRESHOLD};
use veridos_journal::journal::mac;
use veridos_journal::journal::{EventKind, Journal, Record, TaintFlags};

const ROOT: [u8; 32] = [7u8; 32];
const PINNED_HASH: &str = "2f80d5c835fe002a67ab0e990cb2a217c2186292009fef72b77367c5d00c8b19";
const PINNED_RECORDS: usize = 1292;
const PINNED_CAS_OBJECTS: usize = 641;

fn mk(epoch: u32, domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, epoch), domain)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Независимая реализация генератора diff-v2 по брифу TASK-006.
fn independent_scenario() -> Journal {
    let sizes = [0usize, 100, 4096, 4097, 5000, 8192, 12000];
    let mut journal = Journal::new();
    let mut i = 0u64;
    while i < 1200 {
        let epoch = (i / 300) as u32;
        let domain = (i % 3) as u8;
        let actor = i % 5;
        let key = mk(epoch, domain);
        let kind = EventKind::from_u8((i % 16) as u8).unwrap();
        let size = sizes[(i % 7) as usize];
        let seed = i / 7;
        let payload: Vec<u8> = (0..size).map(|k| ((seed + k as u64) % 256) as u8).collect();

        if kind == EventKind::Validate {
            let target = journal.len() as u64 - 1;
            let consumer = Record::draft(epoch, domain, i, actor, EventKind::AgentDecision, TaintFlags::empty(), vec![target], Vec::new());
            journal.append(consumer, &key).unwrap();
            let validator = Record::draft(epoch, domain, i, actor, EventKind::Validate, TaintFlags::empty(), vec![target], Vec::new());
            journal.append(validator, &key).unwrap();
        } else {
            let mut causality = Vec::new();
            let len = journal.len() as u64;
            if len > 0 {
                causality.push(len - 1);
            }
            if len > 7 {
                causality.push(len - 7);
            }
            let taint = match i % 4 {
                1 => TaintFlags::EXTERNAL_NET,
                2 => TaintFlags::LLM_OUTPUT | TaintFlags::UNVALIDATED,
                3 => TaintFlags::L2_UNTRUSTED,
                _ => TaintFlags::empty(),
            };
            let rec = Record::draft(epoch, domain, i, actor, kind, taint, causality, payload);
            journal.append(rec, &key).unwrap();
        }

        if i % 100 == 99 {
            let replayed = Record::draft(epoch, domain, i, actor, EventKind::ReplayEvent, TaintFlags::LLM_OUTPUT, Vec::new(), Vec::new());
            journal.append_replayed(replayed, &key).unwrap();
        }
        if i % 200 == 199 {
            journal.checkpoint(epoch, &mk(epoch, 0)).unwrap();
        }
        i += 1;
    }
    journal
}

#[test]
fn independent_generator_reproduces_pinned_diff_v2_hash() {
    let mut journal = independent_scenario();
    assert_eq!(journal.len(), PINNED_RECORDS);
    assert_eq!(journal.cas().len(), PINNED_CAS_OBJECTS);
    assert!(journal.verify_chain(0..journal.len() as u64, &ROOT).is_ok());
    let anchor = journal.anchor();
    journal.replay(0).unwrap();
    assert_eq!(journal.state_hash(), anchor.state_hash);
    assert_eq!(hex(&journal.state_hash()), PINNED_HASH, "независимый генератор обязан совпасть с пином");
}

#[test]
fn cas_dedup_across_epochs_and_domains() {
    let mut journal = Journal::new();
    let big = vec![0xE7u8; THRESHOLD + 1];
    let first = Record::draft(0, 0, 10, 1, EventKind::McpRequest, TaintFlags::empty(), Vec::new(), big.clone());
    let s1 = journal.append(first, &mk(0, 0)).unwrap();
    let second = Record::draft(1, 2, 11, 2, EventKind::McpResponse, TaintFlags::empty(), Vec::new(), big.clone());
    let s2 = journal.append(second, &mk(1, 2)).unwrap();
    assert_ne!(s1, s2);
    assert_eq!(journal.cas().len(), 1, "идентичное содержимое — один объект CAS");
    assert_eq!(journal.get(s1).unwrap().payload, journal.get(s2).unwrap().payload);
    let hash: [u8; 32] = journal.get(s1).unwrap().payload.clone().try_into().unwrap();
    assert_eq!(journal.cas().get(&hash).unwrap(), big.as_slice());
    assert!(journal.verify_chain(0..2, &ROOT).is_ok());
}

#[test]
fn threshold_boundary_on_single_records() {
    let mut journal = Journal::new();
    let inline = vec![0x11u8; THRESHOLD];
    journal.append(draft_big(EventKind::TaskStart, 0, inline), &mk(0, 0)).unwrap();
    assert!(journal.cas().is_empty(), "ровно 4096 остаётся inline");
    assert_eq!(journal.get(0).unwrap().payload.len(), THRESHOLD);

    let carried = vec![0x22u8; THRESHOLD + 1];
    journal.append(draft_big(EventKind::TaskEnd, 1, carried.clone()), &mk(0, 0)).unwrap();
    assert_eq!(journal.cas().len(), 1);
    let stored = journal.get(1).unwrap();
    assert_eq!(stored.payload.len(), 32);
    let hash: [u8; 32] = stored.payload.clone().try_into().unwrap();
    assert_eq!(hash, *blake3::hash(&carried).as_bytes());
}

fn draft_big(kind: EventKind, source_seq: u64, payload: Vec<u8>) -> Record {
    Record::draft(0, 0, source_seq, 0, kind, TaintFlags::empty(), Vec::new(), payload)
}

#[test]
fn replay_from_any_point_matches_suffix_rebuild() {
    let mut journal = independent_scenario();
    let records: Vec<Record> = journal.iter().cloned().collect();
    // Границы checkpoint и произвольные точки, включая середину CAS-записей.
    for k in [0u64, 199, 200, 399, 601, 999, 1200] {
        journal.replay(k).unwrap();
        let suffix = Journal::from_records_unchecked(records[k as usize..].to_vec(), Cas::new());
        assert_eq!(journal.state_hash(), suffix.state_hash(), "replay({k}) != суффикс");
    }
    // Полный replay возвращает пинный хеш.
    journal.replay(0).unwrap();
    assert_eq!(hex(&journal.state_hash()), PINNED_HASH);
}

#[test]
fn cas_content_is_outside_chain_coverage_v0_limitation() {
    let journal = independent_scenario();
    let records: Vec<Record> = journal.iter().cloned().collect();
    let hash_before = journal.state_hash();

    // Отсутствие объектов CAS: цепочка и state_hash этого НЕ видят
    // (payload записи — только хеш-ссылка). Ограничение v0-заглушки.
    let rebuilt = Journal::from_records_unchecked(records.clone(), Cas::new());
    assert!(rebuilt.verify_chain(0..rebuilt.len() as u64, &ROOT).is_ok());
    assert_eq!(rebuilt.state_hash(), hash_before);
    assert!(rebuilt.cas().is_empty());

    // Прямая сверка адрес=содержимое обнаруживает отсутствие объекта.
    let carried: Vec<&Record> = records
        .iter()
        .filter(|r| r.payload.len() == 32 && r.kind != EventKind::Checkpoint)
        .collect();
    assert!(!carried.is_empty());
    for rec in carried {
        let hash: [u8; 32] = rec.payload.clone().try_into().unwrap();
        let data = journal.cas().get(&hash).expect("объект в исходном CAS");
        assert_eq!(*blake3::hash(data).as_bytes(), hash);
        assert!(rebuilt.cas().get(&hash).is_none());
    }
}