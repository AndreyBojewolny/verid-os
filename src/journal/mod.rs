//! Модуль журнала: детерминированные записи с криптографической целостностью.
//! См. specs/veridos_journal_spec_v0.1.md.

pub mod cas;
pub mod cbor;
pub mod chain;
pub mod mac;
pub mod record;

pub use chain::{AppendError, Journal, ReplayError, VerifyError, WarnSink};
pub use record::{EventKind, Record, TaintFlags};