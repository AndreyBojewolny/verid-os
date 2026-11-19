//! Capability-граф по журналу: CapGrant/CapRevoke, overgrant_diff, surface.
//!
//! Соглашения v0:
//! - payload событий CapGrant/CapRevoke/McpRequest — канонический CBOR text
//!   string с именем capability; записи с иным payload графом игнорируются.
//! - human-grant — CapGrant в домене 0 (L0, владелец).
//! - использование capability — McpRequest актора-держателя с именем capability
//!   в payload.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;
use core::ops::Range;

use crate::journal::{EventKind, Journal};

/// Capability-граф: актор -> множество действующих capability.
/// human_granted — пары (актор, capability), выданные явным human-grant
/// (CapGrant в домене 0) и впоследствии не отозванные.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityGraph {
    grants: BTreeMap<u64, BTreeSet<String>>,
    human_granted: BTreeSet<(u64, String)>,
}

/// Расширение прав между двумя графами.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OvergrantDiff {
    /// true, если after содержит хотя бы одну пару, отсутствовавшую в before.
    pub expanded: bool,
    /// Добавленные пары (актор, capability), отсортированы детерминированно.
    pub added: Vec<(u64, String)>,
}

/// Ретроспективный отчёт overgrant surface за окно записей.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceReport {
    /// Число действующих грантов на конец окна.
    pub granted: usize,
    /// Из них использовались (McpRequest держателя) внутри окна.
    pub used: usize,
    /// Неиспользованные пары (актор, capability), детерминированный порядок.
    pub unused: Vec<(u64, String)>,
}

/// Ошибка построения отчёта surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceError {
    /// Окно выходит за пределы журнала или start > end.
    OutOfRange,
}

/// Канонический CBOR payload события capability (text string).
/// Гарантирует: детерминированный результат бит-в-бит для одинакового имени.
pub fn encode_cap(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Text(name.into()), &mut buf)
        .expect("запись CBOR в Vec не может завершиться ошибкой ввода-вывода");
    buf
}

/// Разбор payload события capability. Гарантирует: None для любого payload,
/// не являющегося CBOR text string (такие записи граф игнорирует).
pub fn decode_cap(payload: &[u8]) -> Option<String> {
    match ciborium::de::from_reader::<Value, _>(payload) {
        Ok(Value::Text(name)) => Some(name),
        _ => None,
    }
}

impl CapabilityGraph {
    /// Граф по всему журналу. Гарантирует: детерминированность (порядок seq);
    /// CapGrant добавляет пару, CapRevoke удаляет пару и её human-grant статус;
    /// записи других видов и с не-CBOR-text payload не влияют на граф.
    pub fn from_journal(journal: &Journal) -> Self {
        let mut graph = Self::default();
        for rec in journal.iter() {
            graph.apply(rec.kind, rec.domain, rec.actor, &rec.payload);
        }
        graph
    }

    /// Граф по окну записей [start, end). Гарантирует: те же правила, что
    /// from_journal, ограниченные окном; OutOfRange для неверного окна.
    pub fn from_journal_range(journal: &Journal, window: Range<u64>) -> Result<Self, SurfaceError> {
        check_window(journal, &window)?;
        let mut graph = Self::default();
        for rec in journal.iter().skip(window.start as usize).take((window.end - window.start) as usize) {
            graph.apply(rec.kind, rec.domain, rec.actor, &rec.payload);
        }
        Ok(graph)
    }

    fn apply(&mut self, kind: EventKind, domain: u8, actor: u64, payload: &[u8]) {
        let name = match kind {
            EventKind::CapGrant | EventKind::CapRevoke => match decode_cap(payload) {
                Some(name) => name,
                None => return,
            },
            _ => return,
        };
        match kind {
            EventKind::CapGrant => {
                self.grants.entry(actor).or_default().insert(name.clone());
                if domain == 0 {
                    self.human_granted.insert((actor, name));
                }
            }
            EventKind::CapRevoke => {
                if let Some(set) = self.grants.get_mut(&actor) {
                    set.remove(&name);
                }
                self.human_granted.remove(&(actor, name));
            }
            _ => {}
        }
    }

    /// Действующие capability актора. Гарантирует: пустое множество для
    /// неизвестного актора.
    pub fn capabilities(&self, actor: u64) -> BTreeSet<String> {
        self.grants.get(&actor).cloned().unwrap_or_default()
    }

    /// Все действующие пары (актор, capability) в детерминированном порядке.
    pub fn pairs(&self) -> Vec<(u64, String)> {
        self.grants
            .iter()
            .flat_map(|(&actor, caps)| caps.iter().map(move |cap| (actor, cap.clone())))
            .collect()
    }

    /// Пары, выданные явным human-grant (домен 0) и не отозванные.
    pub fn human_granted(&self) -> &BTreeSet<(u64, String)> {
        &self.human_granted
    }
}

/// Расширение прав: пары из after, отсутствующие в before.
/// Гарантирует: детерминированный порядок added; отзыв или отсутствие
/// изменений дают expanded == false и пустой added.
pub fn overgrant_diff(before: &CapabilityGraph, after: &CapabilityGraph) -> OvergrantDiff {
    let before_pairs: BTreeSet<(u64, String)> = before.pairs().into_iter().collect();
    let added: Vec<(u64, String)> = after
        .pairs()
        .into_iter()
        .filter(|pair| !before_pairs.contains(pair))
        .collect();
    OvergrantDiff { expanded: !added.is_empty(), added }
}

/// Ретроспективный overgrant surface за окно [start, end): какие действующие
/// capability не использовались (не было McpRequest держателя с этим именем).
/// Гарантирует: детерминированность отчёта; использование засчитывается только
/// внутри окна; OutOfRange для неверного окна.
pub fn overgrant_surface(journal: &Journal, window: Range<u64>) -> Result<SurfaceReport, SurfaceError> {
    check_window(journal, &window)?;
    let graph = CapabilityGraph::from_journal_range(journal, window.clone())?;
    let mut used: BTreeSet<(u64, String)> = BTreeSet::new();
    for rec in journal.iter().skip(window.start as usize).take((window.end - window.start) as usize) {
        if rec.kind == EventKind::McpRequest {
            if let Some(name) = decode_cap(&rec.payload) {
                let pair = (rec.actor, name);
                if graph.grants.get(&pair.0).is_some_and(|caps| caps.contains(&pair.1)) {
                    used.insert(pair);
                }
            }
        }
    }
    let pairs = graph.pairs();
    let granted = pairs.len();
    let unused: Vec<(u64, String)> = pairs.into_iter().filter(|pair| !used.contains(pair)).collect();
    Ok(SurfaceReport { granted, used: granted - unused.len(), unused })
}

fn check_window(journal: &Journal, window: &Range<u64>) -> Result<(), SurfaceError> {
    if window.start > window.end || window.end > journal.len() as u64 {
        return Err(SurfaceError::OutOfRange);
    }
    Ok(())
}