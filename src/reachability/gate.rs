//! Гейт эволюции: CodeUpdate не расширяет собственные права (инвариант
//! конституции). Нарушение -> отклонение + DlqEntry в журнале.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::journal::{AppendError, EventKind, Journal, Record, TaintFlags};

use super::graph::{encode_cap, overgrant_diff, CapabilityGraph};

/// Решение гейта по CodeUpdate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateVerdict {
    /// Пост-условие выполнено: суммарный capability-set не расширен
    /// (либо расширение целиком покрыто явными human-grant).
    Allow,
    /// Расширение прав без human-grant: обновление отклонено,
    /// в журнал добавлена запись DlqEntry с флагом DLQ.
    Reject { added: Vec<(u64, String)>, dlq_seq: u64 },
}

/// Проверка CodeUpdate на «не расширяет overgrant».
/// before — граф до обновления, after — граф после (симуляция).
/// Гарантирует: расширение без human-grant (CapGrant домена 0 в after)
/// всегда отклоняется и журналируется как DlqEntry (taint DLQ, домен 0);
/// ослабление и отсутствие изменений проходят без записей в журнал;
/// вердикт детерминирован по содержимому графов. Ключ — только параметр.
pub fn gate_code_update(
    journal: &mut Journal,
    mac_key: &[u8; 32],
    epoch: u32,
    update_actor: u64,
    before: &CapabilityGraph,
    after: &CapabilityGraph,
) -> Result<GateVerdict, AppendError> {
    let diff = overgrant_diff(before, after);
    if !diff.expanded {
        return Ok(GateVerdict::Allow);
    }
    let unauthorized: Vec<(u64, String)> = diff
        .added
        .into_iter()
        .filter(|pair| !after.human_granted().contains(pair))
        .collect();
    if unauthorized.is_empty() {
        return Ok(GateVerdict::Allow);
    }

    let summary = unauthorized
        .iter()
        .map(|(actor, cap)| format!("{actor}:{cap}"))
        .collect::<Vec<_>>()
        .join(";");
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
    Ok(GateVerdict::Reject { added: unauthorized, dlq_seq })
}