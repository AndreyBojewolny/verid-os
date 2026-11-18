//! Формат записи журнала.
//! TODO(TASK-001): реализовать по specs/veridos_journal_spec_v0.1.md

use bitflags::bitflags;

bitflags! {
    /// Taint-флаги записи. Наследование: OR(parents) | флаг источника.
    pub struct TaintFlags: u16 {
        const EXTERNAL_NET = 1 << 0;
        const LLM_OUTPUT   = 1 << 1;
        const L2_UNTRUSTED = 1 << 2;
        const UNVALIDATED  = 1 << 3;
        const QUARANTINED  = 1 << 4;
        const VALIDATED    = 1 << 5;
        const EPOCH_REVOKED= 1 << 6;
        const DLQ          = 1 << 7;
        const REPLAYED     = 1 << 8;
    }
}

/// Виды событий — закрытый словарь из 16 значений.
#[derive(Clone, Copy, Debug)]
pub enum EventKind {
    CapGrant, CapRevoke, McpRequest, McpResponse,
    AgentDecision, Validate, Quarantine, DlqEntry,
    Checkpoint, EpochRotate, TaintApply, ReplayEvent,
    TaskStart, TaskEnd, CellSpawn, CellHalt,
}

/// Запись журнала. TODO(TASK-001): канонический CBOR, BLAKE3-хеш, MAC.
#[derive(Clone, Debug)]
pub struct Record {
    pub seq: u64,
    pub epoch: u32,
    pub domain: u8,
    pub source_seq: u64,
    pub causality: Vec<u64>,
    pub actor: u64,
    pub kind: EventKind,
    pub taint: TaintFlags,
    pub payload: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub mac: [u8; 16],
}
