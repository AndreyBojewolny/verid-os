//! Reachability v0 — гейт эволюции (TASK-003).
//! См. specs/veridos_evolution_loop_spec_v0.2.md (Инвариант, В4).
//!
//! Гарантии модуля: no_std (alloc), детерминированность графа, diff и отчётов;
//! расширение прав без явного human-grant отклоняется и попадает в DLQ;
//! capability-события с неканоническим payload помечаются malformed,
//! гейт по ним отклоняет fail-closed. Предусловие: целостность журнала
//! проверена вызывающим (verify_chain/verify_anchor).

pub mod gate;
pub mod graph;

pub use gate::{gate_code_update, GateVerdict};
pub use graph::{
    decode_cap, encode_cap, overgrant_diff, overgrant_surface, CapabilityGraph, OvergrantDiff,
    SurfaceError, SurfaceReport,
};