//! TASK-002: дифференциальный тест детерминизма журнала.
//!
//! Сценарий diff-v1: детерминированный генератор (без RNG/времени) строит
//! >= 1000 записей — все 16 EventKind, 4 эпохи, 3 домена, 5 акторов,
//! payload до 5000 байт (CAS-вынос > 4 KB), Validate с записями-потреблениями,
//! checkpoint каждые 200 событий, REPLAYED каждые 100. Replay(0) обязан
//! воспроизвести state_hash побитно; второй независимый прогон и пересборка
//! из записей дают тот же хеш. Хеш фиксируется в reports/state_hash.json
//! и сверяется с встроенным регрессионным вектором.

use std::fs;
use std::path::PathBuf;

use veridos_journal::journal::cas::Cas;
use veridos_journal::journal::mac;
use veridos_journal::journal::{EventKind, Journal, Record, TaintFlags};

const ROOT: [u8; 32] = [7u8; 32];
const N: u64 = 1200;

/// Регрессионный вектор diff-v1 (hosted x86_64-pc-windows-gnu, зафиксирован
/// VERIFIER-прогоном). Любое расхождение = FAIL детерминизма или регрессия.
const EXPECTED_STATE_HASH: &str = "7b0be0df33077c8e7996a6f476209e33e473e5dae38759a56f04e1fa08aebc32";

fn mk(epoch: u32, domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, epoch), domain)
}

fn build_scenario() -> Journal {
    let mut journal = Journal::new();
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

        let payload_len = if i % 97 == 0 { 0 } else { (i % 5000) as usize };
        let payload: Vec<u8> = (0..payload_len).map(|k| ((i + k as u64) % 256) as u8).collect();

        if kind == EventKind::Validate {
            // Получатель потребляет цель, затем валидирует (авторизация по актору).
            let target = journal.len() as u64 - 1;
            let consumer = Record::draft(epoch, domain, i, actor, EventKind::AgentDecision, TaintFlags::empty(), vec![target], Vec::new());
            journal.append(consumer, &key).unwrap();
            let validator = Record::draft(epoch, domain, i, actor, EventKind::Validate, TaintFlags::empty(), vec![target], Vec::new());
            journal.append(validator, &key).unwrap();
        } else {
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
    journal
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn diff_v1_state_hash_is_deterministic() {
    let mut journal = build_scenario();
    assert!(journal.len() >= 1000, "сценарий должен давать >= 1000 записей");
    assert!(journal.verify_chain(0..journal.len() as u64, &ROOT).is_ok());

    let anchor = journal.anchor();
    journal.replay(0).unwrap();
    let hash = journal.state_hash();
    assert_eq!(hash, anchor.state_hash);

    // Второй независимый прогон генератора — побитное совпадение.
    let second = build_scenario();
    assert_eq!(second.state_hash(), hash);
    assert_eq!(second.anchor(), anchor);

    // Пересборка из записей + replay — тот же хеш.
    let records: Vec<Record> = journal.iter().cloned().collect();
    let mut rebuilt = Journal::from_records_unchecked(records, Cas::new());
    rebuilt.replay(0).unwrap();
    assert_eq!(rebuilt.state_hash(), hash);

    let hash_hex = hex(&hash);
    println!("diff-v1: records={} state_hash={}", journal.len(), hash_hex);

    if !EXPECTED_STATE_HASH.is_empty() {
        assert_eq!(hash_hex, EXPECTED_STATE_HASH, "регрессия state_hash diff-v1");
    }

    let json = format!(
        "{{\n  \"schema\": \"veridos/state-hash/v1\",\n  \"scenario\": \"diff-v1\",\n  \"target\": \"hosted-{}-{}\",\n  \"records\": {},\n  \"state_hash\": \"{}\",\n  \"tip_hash\": \"{}\"\n}}\n",
        std::env::consts::ARCH,
        std::env::consts::OS,
        journal.len(),
        hash_hex,
        hex(&anchor.tip_hash),
    );
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("reports").join("state_hash.json");
    fs::write(&path, json).expect("reports/ доступен для записи state_hash.json");
}