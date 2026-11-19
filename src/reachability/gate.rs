//! Гейт эволюции: CodeUpdate не расширяет собственные права (инвариант
//! конституции). Нарушение -> отклонение + DlqEntry в журнале.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeSet;

use crate::journal::{AppendError, EventKind, Journal, Record, TaintFlags};

use super::graph::{encode_cap, overgrant_diff, CapabilityGraph};

/// Решение гейта по CodeUpdate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateVerdict {
    /// Пост-условие выполнено: суммарный capability-set не расширен
    /// (либо расширение целиком покрыто явными human-grant), и оба графа
    /// не содержат malformed capability-событий.
    Allow,
    /// Расширение прав без human-grant и/или malformed capability-события
    /// (граф не видит часть грантов, fail-closed): обновление отклонено,
    /// в журнал добавлена запись DlqEntry с флагом DLQ.
    Reject {
        added: Vec<(u64, String)>,
        malformed: Vec<u64>,
        dlq_seq: u64,
    },
}

/// Проверка CodeUpdate на «не расширяет overgrant».
/// before — граф до обновления, after — граф после (симуляция).
/// Гарантирует: расширение без human-grant (CapGrant домена 0 в after)
/// всегда отклоняется и журналируется как DlqEntry (taint DLQ, домен 0);
/// malformed capability-события в любом из графов отклоняются fail-closed;
/// ослабление и отсутствие изменений без malformed проходят без записей
/// в журнал; вердикт детерминирован по содержимому графов. Ключ — только
/// параметр. Предусловие: целостность журнала проверена вызывающим.
pub fn gate_code_update(
    journal: &mut Journal,
    mac_key: &[u8; 32],
    epoch: u32,
    update_actor: u64,
    before: &CapabilityGraph,
    after: &CapabilityGraph,
) -> Result<GateVerdict, AppendError> {
    let diff = overgrant_diff(before, after);
    let unauthorized: Vec<(u64, String)> = diff
        .added
        .into_iter()
        .filter(|pair| !after.human_granted().contains(pair))
        .collect();
    let malformed: Vec<u64> = before
        .malformed_events()
        .iter()
        .chain(after.malformed_events())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if unauthorized.is_empty() && malformed.is_empty() {
        return Ok(GateVerdict::Allow);
    }

    let mut summary = unauthorized
        .iter()
        .map(|(actor, cap)| format!("{actor}:{cap}"))
        .collect::<Vec<_>>()
        .join(";");
    if !malformed.is_empty() {
        let seqs = malformed
            .iter()
            .map(|seq| format!("{seq}"))
            .collect::<Vec<_>>()
            .join(",");
        summary = format!("{summary}; malformed events: {seqs}");
    }
    let dlq = Record::draft(
        epoch,
        0,
        journal.len() as u64,
        update_actor,
        EventKind::DlqEntry,
        TaintFlags::DLQ,
        Vec::new(),
        encode_cap(&format!("overgrant rejected: {summary}")),
    );
    let dlq_seq = journal.append(dlq, mac_key)?;
    Ok(GateVerdict::Reject { added: unauthorized, malformed, dlq_seq })
}