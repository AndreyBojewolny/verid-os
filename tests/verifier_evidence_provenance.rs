//! Независимая проверка VERIFIER для TASK-009 (provenance свидетельств).
//! Углы, не покрытые тестами Implementer: клеточная телеметрия не «чинит»
//! tainted-базу домена 0, клеточная аномалия триггерит но не авторизует,
//! критерий provenance — домен а не актор, отказ пустой родословной в
//! не-Running состояниях и без вреда для очереди, submit проверяет пустоту
//! а не существование родителя, handle несёт актора/эпоху петли, граница
//! каста допуска (invalid-config vs invalid-baseline), клеточная база не
//! спасает от красной линии 4, детерминизм/replay с клеточным шумом.

use ciborium::value::Value;
use veridos_journal::evolution_loop::{
    payload, CanaryCtx, CanaryOutcome, Config, EvolutionLoop, LoopStatus, MetricsSandbox,
    ProposedUpdate, Sandbox, SubmitError, Target,
};
use veridos_journal::journal::{cas::Cas, mac, AppendError, EventKind, Journal, Record, TaintFlags};

const ROOT: [u8; 32] = [83u8; 32];
const EPOCH: u32 = 3;
const ACTOR: u64 = 163;

fn mk(domain: u8) -> [u8; 32] {
    mac::mac_key(&mac::epoch_key(&ROOT, EPOCH), domain)
}

fn config(pct: u64) -> Config {
    Config { budget: 100, execute_cost: 10, heartbeat_secs: 3600, actor: ACTOR, latency_tolerance_pct: pct }
}

fn tel(journal: &mut Journal, domain: u8, actor: u64, metric: &str, value: i64, anomaly: bool, taint: TaintFlags) -> u64 {
    let rec = Record::draft(
        EPOCH, domain, journal.len() as u64, actor, EventKind::Telemetry,
        taint, Vec::new(), payload::telemetry(metric, value, anomaly),
    );
    journal.append(rec, &mk(domain)).expect("telemetry")
}

fn baseline(journal: &mut Journal, latency: i64, errors: i64) {
    tel(journal, 0, 900, "latency", latency, false, TaintFlags::empty());
    tel(journal, 0, 900, "errors", errors, false, TaintFlags::empty());
}

/// Чистый триггер-якорь: McpResponse не триггерит Monitor.
fn anchor(journal: &mut Journal) -> u64 {
    let rec = Record::draft(
        EPOCH, 0, journal.len() as u64, 900, EventKind::McpResponse,
        TaintFlags::empty(), Vec::new(), Vec::new(),
    );
    journal.append(rec, &mk(0)).expect("anchor")
}

fn upd(caps_add: &[&str], caps_del: &[&str]) -> ProposedUpdate {
    ProposedUpdate {
        target: Target::Cell,
        caps_add: caps_add.iter().map(|s| s.to_string()).collect(),
        caps_del: caps_del.iter().map(|s| s.to_string()).collect(),
        canary_pass: true,
    }
}

fn field(payload_bytes: &[u8], key: &str) -> Option<Value> {
    let Value::Map(map) = ciborium::de::from_reader::<Value, _>(payload_bytes).ok()? else {
        return None;
    };
    map.iter().find(|(k, _)| matches!(k, Value::Text(s) if s == key)).map(|(_, v)| v.clone())
}

fn reason(journal: &Journal) -> Option<Value> {
    let canary = journal.iter().filter(|r| r.kind == EventKind::CanaryResult).last()?;
    field(&canary.payload, "reason")
}

#[test]
fn cell_telemetry_cannot_repair_tainted_domain0_baseline() {
    let mut journal = Journal::new();
    tel(&mut journal, 0, 900, "latency", 200, false, TaintFlags::EXTERNAL_NET);
    tel(&mut journal, 0, 900, "errors", 0, false, TaintFlags::empty());
    // Чистые клеточные измерения не вытесняют tainted-базу домена 0.
    tel(&mut journal, 16, 555, "latency", 200, false, TaintFlags::empty());
    tel(&mut journal, 16, 555, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("tainted-evidence".into())));
}

#[test]
fn cell_anomaly_triggers_but_cannot_authorize() {
    let mut journal = Journal::new();
    // Аномалия клетки (домен 16) триггерит Monitor, но базы домена 0 нет:
    // авто-обновление петли fail-closed откатывается.
    tel(&mut journal, 16, 555, "latency", 999, true, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.triggers, 1);
    assert_eq!(r.hypotheses, 1);
    assert_eq!(r.executed, 0);
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("no-baseline".into())));
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn provenance_criterion_is_domain_not_actor() {
    let mut journal = Journal::new();
    // Домен 0, чужой актор (не монитор 900): решение владельца — критерий
    // домен, а не актор; запись принимается как база.
    tel(&mut journal, 0, 777, "latency", 200, false, TaintFlags::empty());
    tel(&mut journal, 0, 777, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
    assert_eq!(reason(&journal), Some(Value::Text("non-regression".into())));
}

#[test]
fn empty_lineage_rejected_in_non_running_states() {
    // Frozen: отказ не размораживает и не пишет.
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd_l0(), vec![anchor(&mut journal)]).expect("submit");
    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick freeze");
    assert_eq!(lp.status(), LoopStatus::Frozen);
    let len = journal.len();
    assert_eq!(lp.submit(upd(&[], &[]), Vec::new()), Err(SubmitError::EmptyLineage));
    assert_eq!(lp.status(), LoopStatus::Frozen);
    assert_eq!(journal.len(), len);

    // PausedHuman: отказ не снимает паузу и не пишет.
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    for _ in 0..3 {
        lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    }
    lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick pause");
    assert_eq!(lp.status(), LoopStatus::PausedHuman);
    let len = journal.len();
    assert_eq!(lp.submit(upd(&[], &[]), Vec::new()), Err(SubmitError::EmptyLineage));
    assert_eq!(lp.status(), LoopStatus::PausedHuman);
    assert_eq!(journal.len(), len);
}

fn upd_l0() -> ProposedUpdate {
    ProposedUpdate { target: Target::L0, caps_add: Vec::new(), caps_del: Vec::new(), canary_pass: true }
}

#[test]
fn rejected_empty_submit_does_not_disturb_queue() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit valid");
    assert_eq!(lp.submit(upd(&[], &[]), Vec::new()), Err(SubmitError::EmptyLineage));
    // Отказ не тронул очередь: валидное предложение исполняется.
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
    assert_eq!(journal.iter().filter(|rec| rec.kind == EventKind::CodeUpdate).count(), 1);
}

#[test]
fn submit_checks_emptiness_not_existence() {
    let mut journal = Journal::new();
    let mut lp = EvolutionLoop::new(config(25));
    // Несуществующий родитель — не ошибка submit (проверяет только пустоту);
    // отклонение происходит в тике журналом, без побочных эффектов.
    lp.submit(upd(&[], &[]), vec![999]).expect("submit non-empty");
    let result = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None);
    assert_eq!(result, Err(AppendError::UnknownParent(999)));
    assert!(journal.is_empty());
}

struct ActorEpochProbe;

impl Sandbox for ActorEpochProbe {
    fn evaluate(
        &mut self,
        _update: &ProposedUpdate,
        ctx: &mut CanaryCtx<'_>,
    ) -> Result<CanaryOutcome, AppendError> {
        // Чтение через handle видит журнал.
        assert!(!ctx.journal.journal().is_empty());
        let seq = ctx.journal.record_canary("latency", 7)?;
        let rec = ctx.journal.journal().get(seq).expect("canary record");
        assert_eq!(rec.actor, ACTOR, "актор канарейки = актор петли");
        assert_eq!(rec.epoch, EPOCH, "эпоха канарейки = эпоха тика");
        let (metric, value, anomaly, canary) = payload::telemetry_metric(&rec.payload).expect("metric");
        assert_eq!((metric.as_str(), value), ("latency", 7));
        assert!(!anomaly);
        assert!(canary);
        Ok(CanaryOutcome {
            passed: true,
            reason: "non-regression",
            latency_base: None,
            latency_canary: Some(7),
            errors_base: None,
            errors_canary: None,
        })
    }
}

#[test]
fn canary_handle_records_carry_loop_actor_and_epoch() {
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.set_sandbox(Box::new(ActorEpochProbe));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.executed, 1);
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn tolerance_cast_boundary_config_vs_baseline() {
    // pct = i64::MAX представим: try_from успешен, но checked_mul базы
    // переполняется -> invalid-baseline.
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.set_sandbox(Box::new(MetricsSandbox::new(i64::MAX as u64)));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("invalid-baseline".into())));

    // pct = i64::MAX + 1 не представим в i64 -> invalid-config (раньше базы).
    let mut journal = Journal::new();
    baseline(&mut journal, 200, 0);
    let mut lp = EvolutionLoop::new(config(25));
    lp.set_sandbox(Box::new(MetricsSandbox::new(i64::MAX as u64 + 1)));
    lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 1);
    assert_eq!(reason(&journal), Some(Value::Text("invalid-config".into())));
}

#[test]
fn cell_only_baseline_still_pauses_after_three_rollbacks() {
    let mut journal = Journal::new();
    // Клетка кормит петлю «хорошей» телеметрией — это не база и не спасение
    // от красной линии 4: три fail-closed отката -> PausedHuman.
    tel(&mut journal, 16, 555, "latency", 200, false, TaintFlags::empty());
    tel(&mut journal, 16, 555, "errors", 0, false, TaintFlags::empty());
    let mut lp = EvolutionLoop::new(config(25));
    for _ in 0..3 {
        lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
    }
    let r = lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
    assert_eq!(r.rolled_back, 3);
    assert_eq!(r.executed, 0);
    assert_eq!(r.status, LoopStatus::PausedHuman);
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain valid");
}

#[test]
fn deterministic_replay_with_cell_noise() {
    let run = || {
        let mut journal = Journal::new();
        baseline(&mut journal, 200, 0);
        tel(&mut journal, 16, 555, "latency", 1, false, TaintFlags::empty());
        tel(&mut journal, 16, 555, "errors", 5, false, TaintFlags::empty());
        let mut lp = EvolutionLoop::new(config(25));
        lp.submit(upd(&[], &[]), vec![anchor(&mut journal)]).expect("submit");
        lp.tick(&mut journal, &ROOT, EPOCH, 1000, None).expect("tick");
        journal
    };
    let j1 = run();
    let j2 = run();
    assert_eq!(j1.state_hash(), j2.state_hash());
    let hash = j1.state_hash();
    let mut journal = j1;
    journal.verify_chain(0..journal.len() as u64, &ROOT).expect("chain");
    journal.replay(0).expect("replay");
    assert_eq!(journal.state_hash(), hash);
    let rebuilt = Journal::from_records_unchecked(journal.iter().cloned().collect(), Cas::new());
    assert_eq!(rebuilt.state_hash(), hash);
}