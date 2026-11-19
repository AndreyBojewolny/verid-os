//! Формат записи журнала по specs/veridos_journal_spec_v0.1.md.

use alloc::vec::Vec;
use bitflags::bitflags;

bitflags! {
    /// Taint-флаги записи (9 бит). Наследование: OR(taint родителей) | флаг источника.
    /// UNVALIDATED снимается только операцией Validate (запись в журнал).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

impl TaintFlags {
    /// Флаги, о которых журнал предупреждает через sink при append.
    /// Гарантирует: REPLAYED сюда не входит — replay не создаёт побочных эффектов.
    pub const DANGEROUS: TaintFlags = TaintFlags::EXTERNAL_NET
        .union(TaintFlags::LLM_OUTPUT)
        .union(TaintFlags::L2_UNTRUSTED)
        .union(TaintFlags::UNVALIDATED)
        .union(TaintFlags::QUARANTINED)
        .union(TaintFlags::EPOCH_REVOKED)
        .union(TaintFlags::DLQ);
}

/// Виды событий — закрытый словарь из 16 значений (порядок = коды 0..15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    CapGrant,
    CapRevoke,
    McpRequest,
    McpResponse,
    AgentDecision,
    Validate,
    Quarantine,
    DlqEntry,
    Checkpoint,
    EpochRotate,
    TaintApply,
    ReplayEvent,
    TaskStart,
    TaskEnd,
    CellSpawn,
    CellHalt,
}

impl EventKind {
    /// Код события для сериализации. Гарантирует: значение в 0..=15.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Разбор кода события. Гарантирует: None для любого кода вне 0..=15
    /// (словарь закрытый, расширению не подлежит).
    pub fn from_u8(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::CapGrant,
            1 => Self::CapRevoke,
            2 => Self::McpRequest,
            3 => Self::McpResponse,
            4 => Self::AgentDecision,
            5 => Self::Validate,
            6 => Self::Quarantine,
            7 => Self::DlqEntry,
            8 => Self::Checkpoint,
            9 => Self::EpochRotate,
            10 => Self::TaintApply,
            11 => Self::ReplayEvent,
            12 => Self::TaskStart,
            13 => Self::TaskEnd,
            14 => Self::CellSpawn,
            15 => Self::CellHalt,
            _ => return None,
        })
    }
}

/// Запись журнала. Поля seq, prev_hash и mac назначает только L0 (Journal::append);
/// в черновике они должны быть нулевыми — журнал их перезаписывает.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl Record {
    /// Черновик записи для Journal::append. Гарантирует: seq = 0, prev_hash и mac
    /// нулевые (их назначает журнал); остальные поля сохраняются без изменений.
    pub fn draft(
        epoch: u32,
        domain: u8,
        source_seq: u64,
        actor: u64,
        kind: EventKind,
        taint: TaintFlags,
        causality: Vec<u64>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            seq: 0,
            epoch,
            domain,
            source_seq,
            causality,
            actor,
            kind,
            taint,
            payload,
            prev_hash: [0; 32],
            mac: [0; 16],
        }
    }
}