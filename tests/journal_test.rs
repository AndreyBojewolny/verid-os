//! Тесты ядра журнала: создание записи, append, taint_flag.

use veridos_journal::journal::entry::{Journal, JournalEntry};

#[test]
fn create_entry() {
    let entry = JournalEntry::new(1_700_000_000, "task_start", "payload-data", false);
    assert_eq!(entry.timestamp, 1_700_000_000);
    assert_eq!(entry.event_type, "task_start");
    assert_eq!(entry.payload, "payload-data");
    assert!(!entry.taint_flag);
}

#[test]
fn append_entry_to_journal() {
    let mut journal = Journal::new();
    assert!(journal.is_empty());

    journal.append(JournalEntry::new(1, "validate", "p1", false));
    journal.append(JournalEntry::new(2, "quarantine", "p2", false));

    assert_eq!(journal.len(), 2);
    assert_eq!(journal.entries()[0].event_type, "validate");
    assert_eq!(journal.entries()[1].payload, "p2");
}

#[test]
fn tainted_entry_is_flagged_but_not_blocked() {
    let mut journal = Journal::new();
    journal.append(JournalEntry::new(3, "llm_output", "untrusted", true));

    assert_eq!(journal.len(), 1);
    let stored = &journal.entries()[0];
    assert!(stored.taint_flag);
    assert_eq!(stored.payload, "untrusted");
}