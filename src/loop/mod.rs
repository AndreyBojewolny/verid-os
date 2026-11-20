//! Evolution Loop v0 — скелет MAPE-K поверх журнала (TASK-004).
//! См. specs/veridos_evolution_loop_spec_v0.2.md.
//!
//! Гарантии модуля: no_std (alloc), без LLM (model_tier = "rules" в каждой
//! записи решения); 5 красных линий — константы, override не существует;
//! ключи не хранятся (root_key — параметр, доменные ключи выводятся и затираются);
//! все переходы петли журналируются событиями EvolutionCycle; исход канарейки
//! определяет независимый checker MetricsSandbox (TASK-008), а не самооценка
//! генератора; база non-regression — только доверенная телеметрия домена 0,
//! родословная submit обязательна (TASK-009).

pub mod engine;
pub mod payload;

pub use engine::{
    CanaryCtx, CanaryJournal, Config, EvolutionLoop, LoopStatus, MetricsSandbox, ProposedUpdate,
    RulesSandbox, Sandbox, SubmitError, TickReport, Tier, MAX_CONSECUTIVE_ROLLBACKS,
    MAX_OVERGRANT_ATTEMPTS_PER_EPOCH,
};
pub use payload::{CanaryOutcome, Target};