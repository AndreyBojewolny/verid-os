//! VeridOS journal — детерминированный журнал с криптографической целостностью.
//! См. specs/veridos_journal_spec_v0.1.md
//!
//! Гарантии модуля: ядро no_std (alloc), ключи не хранятся в структурах,
//! сериализация записей каноническая (бит-в-бит), целостность — BLAKE3 MAC
//! и хеш-цепочка.

#![no_std]

extern crate alloc;

pub mod journal;