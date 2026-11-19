//! Движок петли MAPE-K (v0: правила, без LLM).
//!
//! Красные линии (константы конституции, override не существует):
//! 1. Изменение L0 -> Frozen, ожидание владельца.
//! 2. Расхождение state_hash -> Frozen + checkpoint-консервация + алерт (приоритет 0).
//! 3. Расширение собственных прав -> откат + DLQ + алерт; 3 попытки за эпоху -> Stopped.
//! 4. Три подряд canary-отката -> PausedHuman.
//! 5. Исчерпание бюджета -> деградация A->B->C (не тишина).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::journal::cas::Cas;
use crate::journal::{mac, AppendError, EventKind, Journal, Record, TaintFlags, WarnSink};
use crate::reachability::{gate_code_update, CapabilityGraph, GateVerdict};
use crate::reachability::graph::encode_cap;

use super::payload::{self, Target};

/// Порог красной линии 3: попыток расширения прав за эпоху до полной остановки.
pub const MAX_OVERGRANT_ATTEMPTS_PER_EPOCH: u32 = 3;
/// Порог красной линии 4: подряд canary-откатов до паузы.
pub const MAX_CONSECUTIVE_ROLLBACKS: u32 = 3;

/// Ярус деградации (В5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Полный: анализ + модификации (правила).
    A,
    /// Эконом: только анализ и очередь гипотез, модификации запрещены.
    B,
    /// Заморозка: только heartbeat-записи.
    C,
}

/// Состояние петли.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopStatus {
    Running,
    /// Красная линия 4: пауза до человека.
    PausedHuman,
    /// Красные линии 1/2: заморозка до владельца.
    Frozen,
    /// Красная линия 3: полная остановка до ручного разбора.
    Stopped,
}

/// Конфиг петли (задаётся владельцем).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Бюджет условных единиц на период.
    pub budget: u64,
    /// Стоимость одного Execute.
    pub execute_cost: u64,
    /// Интервал heartbeat в ярусе C, секунды.
    pub heartbeat_secs: u64,
    /// Актор петли в журнале.
    pub actor: u64,
}

/// Предложение генератора (Plan). v0: правила или внешняя очередь.
#[derive(Clone, Debug)]
pub struct ProposedUpdate {
    pub target: Target,
    pub caps_add: Vec<String>,
    pub caps_del: Vec<String>,
    /// Вход заглушки песочницы: детерминированный исход canary.
    pub canary_pass: bool,
}

/// Песочница Execute (заглушка v0). Реализация не должна паниковать.
pub trait Sandbox {
    /// true = canary прошёл, false = регресс (откат).
    fn evaluate(&mut self, update: &ProposedUpdate) -> bool;
}

/// Заглушка по умолчанию: исход задаётся предложением детерминированно.
pub struct RulesSandbox;

impl Sandbox for RulesSandbox {
    fn evaluate(&mut self, update: &ProposedUpdate) -> bool {
        update.canary_pass
    }
}

/// Итог тика.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickReport {
    pub triggers: u32,
    pub hypotheses: u32,
    pub executed: u32,
    pub rejected: u32,
    pub rolled_back: u32,
    pub tier: Tier,
    pub status: LoopStatus,
}

/// Петля эволюции поверх журнала. Ключи не хранятся: root_key — параметр тика,
/// доменные ключи выводятся на лету и затираются до возврата.
pub struct EvolutionLoop {
    config: Config,
    tier: Tier,
    status: LoopStatus,
    last_seq: u64,
    consecutive_rollbacks: u32,
    overgrant_attempts: BTreeMap<u32, u32>,
    budget_left: u64,
    last_heartbeat: u64,
    queue: Vec<(ProposedUpdate, Vec<u64>)>,
    hypothesis_queue: Vec<String>,
    sandbox: Box<dyn Sandbox>,
    sink: Option<Box<dyn WarnSink>>,
}

impl EvolutionLoop {
    /// Новая петля: ярус A, Running, полный бюджет, песочница-заглушка.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            tier: Tier::A,
            status: LoopStatus::Running,
            last_seq: 0,
            consecutive_rollbacks: 0,
            overgrant_attempts: BTreeMap::new(),
            budget_left: config.budget,
            last_heartbeat: 0,
            queue: Vec::new(),
            hypothesis_queue: Vec::new(),
            sandbox: Box::new(RulesSandbox),
            sink: None,
        }
    }

    /// Инъекция приёмника алертов. Гарантирует: алерты идут только в sink.
    pub fn set_sink(&mut self, sink: Box<dyn WarnSink>) {
        self.sink = Some(sink);
    }

    /// Инъекция песочницы (замена заглушки).
    pub fn set_sandbox(&mut self, sandbox: Box<dyn Sandbox>) {
        self.sandbox = sandbox;
    }

    /// Очередь предложений генератора. Гарантирует: порядок FIFO.
    pub fn submit(&mut self, update: ProposedUpdate) {
        self.queue.push((update, Vec::new()));
    }

    /// Текущий ярус деградации.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// Текущее состояние.
    pub fn status(&self) -> LoopStatus {
        self.status
    }

    /// Остаток бюджета.
    pub fn budget_left(&self) -> u64 {
        self.budget_left
    }

    /// Очередь гипотез яруса B (модификации запрещены).
    pub fn hypothesis_queue(&self) -> &[String] {
        &self.hypothesis_queue
    }

    /// Тик петли: Monitor -> Analyze -> Plan -> Execute.
    /// external_state_hash — якорь вызывающего для красной линии 2 (приоритет 0).
    /// Гарантирует: целостность журнала проверяется (verify_chain) до любых
    /// действий; при нарушении — Frozen + алерт, журнал не изменяется
    /// (консервация); красные линии срабатывают до любых модификаций; все записи
    /// решений несут model_tier и наследуют taint триггеров по causality;
    /// ключи выводятся из root_key на лету и затираются; в не-Running
    /// состояниях эволюция не выполняется (только heartbeat в C).
    pub fn tick(
        &mut self,
        journal: &mut Journal,
        root_key: &[u8; 32],
        epoch: u32,
        now: u64,
        external_state_hash: Option<[u8; 32]>,
    ) -> Result<TickReport, AppendError> {
        if journal.verify_chain(0..journal.len() as u64, root_key).is_err() {
            self.status = LoopStatus::Frozen;
            self.alert("RED LINE 2: journal integrity verification failed, evolution frozen, journal left untouched");
            return Ok(TickReport {
                triggers: 0,
                hypotheses: 0,
                executed: 0,
                rejected: 0,
                rolled_back: 0,
                tier: self.tier,
                status: self.status,
            });
        }
        let mut epoch_key = mac::epoch_key(root_key, epoch);
        let mut key0 = mac::mac_key(&epoch_key, 0);
        let mut key16 = mac::mac_key(&epoch_key, 16);
        let result = self.tick_inner(journal, epoch, now, external_state_hash, &key0, &key16);
        mac::zeroize_key(&mut epoch_key);
        mac::zeroize_key(&mut key0);
        mac::zeroize_key(&mut key16);
        result
    }

    /// Действие владельца: разморозка после ручного разбора.
    /// Гарантирует: сбрасывает статус, счётчики откатов и попыток; журналируется;
    /// ключи затираются на всех путях возврата.
    pub fn owner_resume(
        &mut self,
        journal: &mut Journal,
        root_key: &[u8; 32],
        epoch: u32,
    ) -> Result<(), AppendError> {
        let mut epoch_key = mac::epoch_key(root_key, epoch);
        let mut key0 = mac::mac_key(&epoch_key, 0);
        let result = self.resume_inner(journal, epoch, &key0);
        mac::zeroize_key(&mut epoch_key);
        mac::zeroize_key(&mut key0);
        result
    }

    fn resume_inner(
        &mut self,
        journal: &mut Journal,
        epoch: u32,
        key0: &[u8; 32],
    ) -> Result<(), AppendError> {
        self.status = LoopStatus::Running;
        self.consecutive_rollbacks = 0;
        self.overgrant_attempts.clear();
        self.cycle(journal, epoch, key0, "resume", "owner manual review done")
    }

    fn tick_inner(
        &mut self,
        journal: &mut Journal,
        epoch: u32,
        now: u64,
        external_state_hash: Option<[u8; 32]>,
        key0: &[u8; 32],
        key16: &[u8; 32],
    ) -> Result<TickReport, AppendError> {
        let mut report = TickReport {
            triggers: 0,
            hypotheses: 0,
            executed: 0,
            rejected: 0,
            rolled_back: 0,
            tier: self.tier,
            status: self.status,
        };

        // Красная линия 2 (приоритет 0): расхождение state_hash.
        if let Some(external) = external_state_hash {
            if external != journal.state_hash() {
                self.status = LoopStatus::Frozen;
                journal.checkpoint(epoch, key0)?;
                self.cycle(journal, epoch, key0, "freeze", "state_hash divergence")?;
                self.alert("RED LINE 2: state_hash divergence, evolution frozen, journal checkpointed");
                report.status = self.status;
                return Ok(report);
            }
        }

        if self.status != LoopStatus::Running {
            self.heartbeat(journal, epoch, now, key0)?;
            report.status = self.status;
            return Ok(report);
        }

        if self.tier == Tier::C {
            self.heartbeat(journal, epoch, now, key0)?;
            report.tier = self.tier;
            return Ok(report);
        }

        // Monitor: триггеры из новых записей журнала (cause + seq источника).
        let mut causes: Vec<(String, u64)> = Vec::new();
        for rec in journal.iter().skip(self.last_seq as usize) {
            match rec.kind {
                EventKind::Telemetry => {
                    if let Some((metric, value)) = payload::telemetry_anomaly(&rec.payload) {
                        causes.push((format!("telemetry:{metric}={value}"), rec.seq));
                    }
                }
                EventKind::TaskEnd => causes.push((format!("task_end:{}", rec.seq), rec.seq)),
                _ => {}
            }
        }
        report.triggers = causes.len() as u32;

        // Красная линия 5: исчерпание бюджета -> деградация, не тишина.
        // B->C только когда анализировать нечего (B ещё анализирует триггеры).
        if self.budget_left == 0 {
            if self.tier == Tier::A {
                self.degrade(journal, epoch, now, key0)?;
            } else if self.tier == Tier::B && causes.is_empty() {
                self.degrade(journal, epoch, now, key0)?;
                report.tier = self.tier;
                return Ok(report);
            }
        }

        // Analyze: гипотезы по правилам; causality наследует taint триггера.
        for (cause, trigger_seq) in &causes {
            let hyp_seq = self.append(
                journal,
                epoch,
                key0,
                EventKind::Hypothesis,
                payload::hypothesis(cause),
                alloc::vec![*trigger_seq],
            )?;
            report.hypotheses += 1;
            if self.tier == Tier::B {
                self.hypothesis_queue.push(cause.clone());
            } else {
                // Plan (правила): аномалия -> доброкачественное обновление клетки.
                self.queue.push((
                    ProposedUpdate {
                        target: Target::Cell,
                        caps_add: Vec::new(),
                        caps_del: Vec::new(),
                        canary_pass: true,
                    },
                    alloc::vec![hyp_seq],
                ));
            }
        }

        // Execute: только ярус A.
        if self.tier == Tier::A {
            let queue = core::mem::take(&mut self.queue);
            let ctx = ExecCtx { epoch, key0, key16 };
            for (update, causality) in queue {
                match self.execute(journal, &ctx, &update, &causality, &mut report)? {
                    ExecOutcome::Continue => {}
                    ExecOutcome::Halt => break,
                }
                if self.status != LoopStatus::Running {
                    break;
                }
                if self.budget_left == 0 {
                    self.degrade(journal, epoch, now, key0)?;
                    if self.tier != Tier::A {
                        break;
                    }
                }
            }
        }

        self.last_seq = journal.len() as u64;
        report.tier = self.tier;
        report.status = self.status;
        Ok(report)
    }

    fn execute(
        &mut self,
        journal: &mut Journal,
        ctx: &ExecCtx<'_>,
        update: &ProposedUpdate,
        causality: &[u64],
        report: &mut TickReport,
    ) -> Result<ExecOutcome, AppendError> {
        let &ExecCtx { epoch, key0, key16 } = ctx;
        // Красная линия 1: любое изменение L0 — заморозка до владельца.
        if update.target == Target::L0 {
            self.status = LoopStatus::Frozen;
            self.cycle(journal, epoch, key0, "freeze", "L0 modification attempt")?;
            self.alert("RED LINE 1: L0 modification attempt, waiting for owner");
            return Ok(ExecOutcome::Halt);
        }

        let update_seq = self.append(
            journal,
            epoch,
            key0,
            EventKind::CodeUpdate,
            payload::code_update(update.target, &update.caps_add, &update.caps_del),
            causality.to_vec(),
        )?;

        // Сама петля запрещена по построению (CapabilityViolation) — красная линия 3.
        if update.target == Target::Loop {
            self.cycle(journal, epoch, key0, "violation", "self-modification attempt")?;
            self.alert("RED LINE 3: loop self-modification attempt rejected");
            report.rejected += 1;
            return self.count_attempt(journal, epoch, key0);
        }

        // Гейт reachability: суммарный capability-set после <= до,
        // исключение — явные human-grant.
        let before = CapabilityGraph::from_journal(journal);
        let records: Vec<Record> = journal.iter().cloned().collect();
        let mut sim = Journal::from_records_unchecked(records, Cas::new());
        for cap in &update.caps_add {
            sim.append(
                Record::draft(epoch, 16, sim.len() as u64, self.config.actor, EventKind::CapGrant, TaintFlags::empty(), Vec::new(), encode_cap(cap)),
                key16,
            )?;
        }
        for cap in &update.caps_del {
            sim.append(
                Record::draft(epoch, 16, sim.len() as u64, self.config.actor, EventKind::CapRevoke, TaintFlags::empty(), Vec::new(), encode_cap(cap)),
                key16,
            )?;
        }
        let after = CapabilityGraph::from_journal(&sim);
        if let GateVerdict::Reject { .. } = gate_code_update(journal, key0, epoch, self.config.actor, &before, &after)? {
            self.cycle(journal, epoch, key0, "rollback", "overgrant rejected by reachability gate")?;
            self.alert("RED LINE 3: overgrant attempt, rolled back, DLQ written");
            report.rejected += 1;
            return self.count_attempt(journal, epoch, key0);
        }

        // Песочница (заглушка) + canary.
        let passed = self.sandbox.evaluate(update);
        self.append(
            journal,
            epoch,
            key0,
            EventKind::CanaryResult,
            payload::canary_result(passed, update_seq),
            alloc::vec![update_seq],
        )?;
        if !passed {
            // Автооткат: изменения не применяются.
            self.cycle(journal, epoch, key0, "rollback", "canary regression")?;
            self.alert("canary regression, update rolled back");
            report.rolled_back += 1;
            self.consecutive_rollbacks += 1;
            // Красная линия 4: три подряд отката — пауза до человека.
            if self.consecutive_rollbacks >= MAX_CONSECUTIVE_ROLLBACKS {
                self.status = LoopStatus::PausedHuman;
                self.cycle(journal, epoch, key0, "pause", "three consecutive non-regression rollbacks")?;
                self.alert("RED LINE 4: three consecutive rollbacks, paused until human");
                return Ok(ExecOutcome::Halt);
            }
            return Ok(ExecOutcome::Continue);
        }

        // Применение: гранты/отзывы capability в журнал.
        for cap in &update.caps_add {
            self.append(journal, epoch, key16, EventKind::CapGrant, encode_cap(cap), alloc::vec![update_seq])?;
        }
        for cap in &update.caps_del {
            self.append(journal, epoch, key16, EventKind::CapRevoke, encode_cap(cap), alloc::vec![update_seq])?;
        }
        self.consecutive_rollbacks = 0;
        self.budget_left = self.budget_left.saturating_sub(self.config.execute_cost);
        report.executed += 1;
        Ok(ExecOutcome::Continue)
    }

    fn count_attempt(
        &mut self,
        journal: &mut Journal,
        epoch: u32,
        key0: &[u8; 32],
    ) -> Result<ExecOutcome, AppendError> {
        let attempts = self.overgrant_attempts.entry(epoch).or_insert(0);
        *attempts += 1;
        if *attempts >= MAX_OVERGRANT_ATTEMPTS_PER_EPOCH {
            self.status = LoopStatus::Stopped;
            self.cycle(journal, epoch, key0, "stop", "three overgrant attempts in epoch")?;
            self.alert("RED LINE 3: three overgrant attempts in epoch, FULL STOP until manual review");
            return Ok(ExecOutcome::Halt);
        }
        Ok(ExecOutcome::Continue)
    }

    fn degrade(
        &mut self,
        journal: &mut Journal,
        epoch: u32,
        now: u64,
        key0: &[u8; 32],
    ) -> Result<(), AppendError> {
        let (from, to) = match self.tier {
            Tier::A => ("A", Tier::B),
            Tier::B => ("B", Tier::C),
            Tier::C => return Ok(()),
        };
        self.tier = to;
        if to == Tier::C {
            self.last_heartbeat = now;
        }
        self.cycle(journal, epoch, key0, "degrade", &format!("budget exhausted {from}->{:?}", to))?;
        self.alert(&format!("RED LINE 5: budget exhausted, degraded {from}->{to:?}"));
        Ok(())
    }

    fn heartbeat(
        &mut self,
        journal: &mut Journal,
        epoch: u32,
        now: u64,
        key0: &[u8; 32],
    ) -> Result<(), AppendError> {
        if self.tier == Tier::C && now.saturating_sub(self.last_heartbeat) >= self.config.heartbeat_secs {
            self.last_heartbeat = now;
            self.cycle(journal, epoch, key0, "heartbeat", "tier C alive")?;
        }
        Ok(())
    }

    fn cycle(
        &mut self,
        journal: &mut Journal,
        epoch: u32,
        key0: &[u8; 32],
        phase: &str,
        detail: &str,
    ) -> Result<(), AppendError> {
        self.append(journal, epoch, key0, EventKind::EvolutionCycle, payload::evolution_cycle(phase, detail), Vec::new())?;
        Ok(())
    }

    fn append(
        &mut self,
        journal: &mut Journal,
        epoch: u32,
        key: &[u8; 32],
        kind: EventKind,
        payload: Vec<u8>,
        causality: Vec<u64>,
    ) -> Result<u64, AppendError> {
        let domain = if kind == EventKind::CapGrant || kind == EventKind::CapRevoke { 16 } else { 0 };
        let rec = Record::draft(
            epoch,
            domain,
            journal.len() as u64,
            self.config.actor,
            kind,
            TaintFlags::empty(),
            causality,
            payload,
        );
        journal.append(rec, key)
    }

    fn alert(&mut self, message: &str) {
        if let Some(sink) = &mut self.sink {
            sink.warn(message);
        }
    }
}

enum ExecOutcome {
    Continue,
    Halt,
}

struct ExecCtx<'a> {
    epoch: u32,
    key0: &'a [u8; 32],
    key16: &'a [u8; 32],
}