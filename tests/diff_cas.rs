//! TASK-006: дифференциальный тест детерминизма CAS-выноса (diff-v2).
//!
//! Сценарий diff-v2: детерминированный генератор (без RNG/времени) строит
//! не менее 1000 записей с payload-паттерном вокруг порога CAS (4096): большие
//! payload выносятся в CAS, в записи остаётся 32-байтный BLAKE3-хеш.
//! Replay(0) обязан воспроизвести state_hash побитно; второй независимый
//! прогон и пересборка из записей + CAS дают тот же хеш и якорь. Хеш
//! фиксируется в reports/state_hash_cas.json и сверяется с регрессионным
//! вектором. Пин diff-v1 (tests/diff_state_hash.rs) не затрагивается.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use veridos_journal::journal::cas::THRESHOLD;
use veridos_journal::journal::mac;
use veridos_journal::journal::{EventKind, Journal, Record, TaintFlags};

const ROOT: [u8; 32] = [7u8; 32];
const N: u64 = 1200;
const LEN_PATTERN: [usize; 7] = [0, 100, THRESHOLD, THRESHOLD + 1, 5000, 8192, 12000];

/// Регрессионный вектор diff-v2 (hosted x86_64-pc-windows-gnu, зафиксирован
/// IMPLEMENTER-прогоном, подлежит независимой сверке VERIFIER).
/// Любое расхождение = FAIL детерминизма или регрессия.
const EXPECTED_STATE_HASH: &str = "2f80d5c835fe002a67ab0e990cb2a217c2186292009fef72b77367c5d00c8b19";

fn mk(epoch: u32, domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, epoch), domain)
}

/// Содержимое зависит от seed = i/7: записи i и i+7 с одинаковым классом
/// длины несут идентичные байты — проверка дедупликации CAS по содержимому.
fn payload_for(i: u64) -> Vec<u8> {
    let len = LEN_PATTERN[(i % 7) as usize];
    let seed = i / 7;
    (0..len).map(|k| ((seed + k as u64) % 256) as u8).collect()
}

fn build_scenario() -> (Journal, BTreeSet<[u8; 32]>) {
    let mut journal = Journal::new();
    let mut expected_cas: BTreeSet<[u8; 32]> = BTreeSet::new();
    for i in 0..N {
        let epoch = (i / 300) as u32;
        let domain = (i % 3) as u8;
        let actor = i % 5;
        let key = mk(epoch, domain);
        let kind = EventKind::from_u8((i % 16) as u8).unwrap();

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

        if kind == EventKind::Validate {
            let target = journal.len() as u64 - 1;
            let consumer = Record::draft(epoch, domain, i, actor, EventKind::AgentDecision, TaintFlags::empty(), vec![target], Vec::new());
            journal.append(consumer, &key).unwrap();
            let validator = Record::draft(epoch, domain, i, actor, EventKind::Validate, TaintFlags::empty(), vec![target], Vec::new());
            journal.append(validator, &key).unwrap();
        } else {
            let payload = payload_for(i);
            if payload.len() > THRESHOLD {
                expected_cas.insert(*blake3::hash(&payload).as_bytes());
            }
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
    }
    (journal, expected_cas)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn diff_v2_cas_state_hash_is_deterministic() {
    let (mut journal, expected_cas) = build_scenario();
    assert!(journal.len() >= 1000, "сценарий должен давать >= 1000 записей");
    assert!(journal.verify_chain(0..journal.len() as u64, &ROOT).is_ok());

    // Вынос в CAS: ровно ожидаемое множество объектов, адрес = хеш содержимого.
    assert!(!expected_cas.is_empty());
    assert_eq!(journal.cas().len(), expected_cas.len());
    for hash in &expected_cas {
        let data = journal.cas().get(hash).expect("объект CAS присутствует");
        assert!(data.len() > THRESHOLD);
        assert_eq!(*blake3::hash(data).as_bytes(), *hash);
    }

    // Граница порога: i=2 (4096) остаётся inline, i=3 (4097) вынесен.
    assert_eq!(journal.get(2).unwrap().payload.len(), THRESHOLD);
    let carried = journal.get(3).unwrap();
    assert_eq!(carried.payload.len(), 32);
    let hash: [u8; 32] = carried.payload.clone().try_into().unwrap();
    assert_eq!(hash, *blake3::hash(&payload_for(3)).as_bytes());
    assert!(journal.cas().get(&hash).is_some());

    let anchor = journal.anchor();
    journal.replay(0).unwrap();
    let hash = journal.state_hash();
    assert_eq!(hash, anchor.state_hash);

    // Второй независимый прогон генератора — побитное совпадение.
    let (second, expected_second) = build_scenario();
    assert_eq!(second.state_hash(), hash);
    assert_eq!(second.anchor(), anchor);
    assert_eq!(expected_second, expected_cas);

    // Пересборка из записей + копия CAS + replay — тот же хеш.
    let records: Vec<Record> = journal.iter().cloned().collect();
    let mut rebuilt = Journal::from_records_unchecked(records, journal.cas().clone());
    assert!(rebuilt.verify_chain(0..rebuilt.len() as u64, &ROOT).is_ok());
    rebuilt.replay(0).unwrap();
    assert_eq!(rebuilt.state_hash(), hash);
    assert_eq!(rebuilt.anchor(), anchor);
    assert_eq!(rebuilt.cas().len(), expected_cas.len());

    let hash_hex = hex(&hash);
    println!(
        "diff-v2: records={} cas_objects={} state_hash={}",
        journal.len(),
        journal.cas().len(),
        hash_hex
    );

    if !EXPECTED_STATE_HASH.is_empty() {
        assert_eq!(hash_hex, EXPECTED_STATE_HASH, "регрессия state_hash diff-v2");
    }

    let json = format!(
        "{{\n  \"schema\": \"veridos/state-hash/v1\",\n  \"scenario\": \"diff-v2\",\n  \"target\": \"hosted-{}-{}\",\n  \"records\": {},\n  \"cas_objects\": {},\n  \"state_hash\": \"{}\",\n  \"tip_hash\": \"{}\"\n}}\n",
        std::env::consts::ARCH,
        std::env::consts::OS,
        journal.len(),
        journal.cas().len(),
        hash_hex,
        hex(&anchor.tip_hash),
    );
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("reports");
    // reports/ gitignored: на fresh clone каталога нет — тест самодостаточен.
    fs::create_dir_all(&dir).expect("reports/ создаётся для записи state_hash_cas.json");
    fs::write(dir.join("state_hash_cas.json"), json).expect("reports/ доступен для записи");
}

#[test]
fn diff_v2_large_event_redelivery_is_idempotent() {
    let (mut journal, _) = build_scenario();
    let len = journal.len();
    let cas_len = journal.cas().len();
    let hash_before = journal.state_hash();

    // Точная повторная доставка события i=3 (большой payload, уже в CAS).
    let dup = Record::draft(
        0, 0, 3, 3, EventKind::McpResponse, TaintFlags::L2_UNTRUSTED,
        vec![2], payload_for(3),
    );
    let seq = journal.append(dup, &mk(0, 0)).unwrap();
    assert_eq!(seq, 3);
    assert_eq!(journal.len(), len);
    assert_eq!(journal.cas().len(), cas_len);
    assert_eq!(journal.state_hash(), hash_before);
    assert!(journal.verify_chain(0..journal.len() as u64, &ROOT).is_ok());
}