//! Канонический CBOR payload событий петли (ключи: длина, затем лексикографика).
//! Каждая запись решения несёт model_tier (пока всегда "rules").

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ciborium::value::Value;

/// Ярус модели, породившей решение. v0: только правила, без LLM.
pub const MODEL_TIER_RULES: &str = "rules";

/// Цель CodeUpdate (градация прав на самомодификацию из спеки).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    L0,
    Cell,
    Policy,
    Loop,
    L2,
}

impl Target {
    /// Строковый код цели для payload. Гарантирует: стабильные коды.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "l0",
            Self::Cell => "cell",
            Self::Policy => "policy",
            Self::Loop => "loop",
            Self::L2 => "l2",
        }
    }
}

fn encode_map(mut entries: Vec<(String, Value)>) -> Vec<u8> {
    entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
    let map = Value::Map(entries.into_iter().map(|(k, v)| (Value::Text(k), v)).collect());
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf)
        .expect("запись CBOR в Vec не может завершиться ошибкой ввода-вывода");
    buf
}

fn text(key: &str, value: &str) -> (String, Value) {
    (key.to_string(), Value::Text(value.to_string()))
}

fn uint(key: &str, value: u64) -> (String, Value) {
    (key.to_string(), Value::Integer(value.into()))
}

fn caps(key: &str, names: &[String]) -> (String, Value) {
    (
        key.to_string(),
        Value::Array(names.iter().map(|n| Value::Text(n.clone())).collect()),
    )
}

/// Payload Telemetry. Гарантирует: канонический CBOR, детерминирован бит-в-бит.
pub fn telemetry(metric: &str, value: i64, anomaly: bool) -> Vec<u8> {
    encode_map(alloc::vec![
        text("metric", metric),
        ("value".to_string(), Value::Integer(value.into())),
        uint("anomaly", u64::from(anomaly)),
    ])
}

/// Payload канареечной Telemetry (симулированный прогон checker'а).
/// Маркер canary=1 отличает измерения прогона от фоновой телеметрии:
/// база non-regression берётся только из фоновых записей.
pub fn canary_telemetry(metric: &str, value: i64) -> Vec<u8> {
    encode_map(alloc::vec![
        text("metric", metric),
        ("value".to_string(), Value::Integer(value.into())),
        uint("anomaly", 0),
        uint("canary", 1),
    ])
}

/// Разбор Telemetry: Some((metric, value, anomaly, canary)) для валидного
/// payload. Гарантирует: None для невалидного payload и флагов вне {0,1}
/// (fail-closed); canary отсутствует = фоновая телеметрия.
pub fn telemetry_metric(payload: &[u8]) -> Option<(String, i64, bool, bool)> {
    let Value::Map(map) = ciborium::de::from_reader::<Value, _>(payload).ok()? else {
        return None;
    };
    let get = |key: &str| map.iter().find(|(k, _)| matches!(k, Value::Text(s) if s == key)).map(|(_, v)| v);
    let anomaly = match get("anomaly")? {
        Value::Integer(i) => i128::from(*i),
        _ => return None,
    };
    if anomaly != 0 && anomaly != 1 {
        return None;
    }
    let metric = match get("metric")? {
        Value::Text(s) => s.clone(),
        _ => return None,
    };
    let value = match get("value")? {
        Value::Integer(i) => i64::try_from(i128::from(*i)).ok()?,
        _ => return None,
    };
    let canary = match get("canary") {
        Some(Value::Integer(i)) => match i128::from(*i) {
            0 => false,
            1 => true,
            _ => return None,
        },
        Some(_) => return None,
        None => false,
    };
    Some((metric, value, anomaly == 1, canary))
}

/// Разбор Telemetry: Some((metric, value)) только если anomaly == 1.
/// Гарантирует: None для невалидного payload и нормальной телеметрии.
pub fn telemetry_anomaly(payload: &[u8]) -> Option<(String, i64)> {
    let (metric, value, anomaly, _canary) = telemetry_metric(payload)?;
    if anomaly {
        Some((metric, value))
    } else {
        None
    }
}

/// Payload Hypothesis (решение Analyze). Гарантирует: model_tier присутствует.
pub fn hypothesis(cause: &str) -> Vec<u8> {
    encode_map(alloc::vec![text("cause", cause), text("model_tier", MODEL_TIER_RULES)])
}

/// Payload CodeUpdate (решение Plan). Гарантирует: model_tier присутствует.
pub fn code_update(target: Target, caps_add: &[String], caps_del: &[String]) -> Vec<u8> {
    encode_map(alloc::vec![
        text("target", target.as_str()),
        caps("caps_add", caps_add),
        caps("caps_del", caps_del),
        text("model_tier", MODEL_TIER_RULES),
    ])
}

/// Исход канарейки: вердикт проверяющего и использованные значения.
/// Значения None — свидетельству нет (fail-closed) либо заглушка не измеряет.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryOutcome {
    /// true = canary прошла (non-regression выполнен).
    pub passed: bool,
    /// Машинная причина вердикта (для журнала и алертов).
    pub reason: &'static str,
    /// Базовая латентность (последняя нормальная до update_seq).
    pub latency_base: Option<i64>,
    /// Канареечная латентность (симулированный прогон).
    pub latency_canary: Option<i64>,
    /// Базовые ошибки.
    pub errors_base: Option<i64>,
    /// Канареечные ошибки.
    pub errors_canary: Option<i64>,
}

/// Payload CanaryResult. Гарантирует: model_tier присутствует, канонический
/// CBOR, детерминирован бит-в-бит; отсутствующие значения кодируются null.
pub fn canary_result(outcome: &CanaryOutcome, update_seq: u64) -> Vec<u8> {
    let opt = |v: Option<i64>| v.map_or(Value::Null, |x| Value::Integer(x.into()));
    encode_map(alloc::vec![
        uint("passed", u64::from(outcome.passed)),
        uint("update_seq", update_seq),
        text("reason", outcome.reason),
        text("model_tier", MODEL_TIER_RULES),
        ("latency_base".to_string(), opt(outcome.latency_base)),
        ("latency_canary".to_string(), opt(outcome.latency_canary)),
        ("errors_base".to_string(), opt(outcome.errors_base)),
        ("errors_canary".to_string(), opt(outcome.errors_canary)),
    ])
}

/// Payload EvolutionCycle (переходы петли: degrade/heartbeat/freeze/...).
/// Гарантирует: model_tier присутствует.
pub fn evolution_cycle(phase: &str, detail: &str) -> Vec<u8> {
    encode_map(alloc::vec![
        text("phase", phase),
        text("detail", detail),
        text("model_tier", MODEL_TIER_RULES),
    ])
}