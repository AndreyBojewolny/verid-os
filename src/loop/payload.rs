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

/// Разбор Telemetry: Some((metric, value)) только если anomaly == 1.
/// Гарантирует: None для невалидного payload и нормальной телеметрии.
pub fn telemetry_anomaly(payload: &[u8]) -> Option<(String, i64)> {
    let Value::Map(map) = ciborium::de::from_reader::<Value, _>(payload).ok()? else {
        return None;
    };
    let get = |key: &str| map.iter().find(|(k, _)| matches!(k, Value::Text(s) if s == key)).map(|(_, v)| v);
    let anomaly = match get("anomaly")? {
        Value::Integer(i) => i128::from(*i),
        _ => return None,
    };
    if anomaly != 1 {
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
    Some((metric, value))
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

/// Payload CanaryResult. Гарантирует: model_tier присутствует.
pub fn canary_result(passed: bool, update_seq: u64) -> Vec<u8> {
    encode_map(alloc::vec![
        uint("passed", u64::from(passed)),
        uint("update_seq", update_seq),
        text("model_tier", MODEL_TIER_RULES),
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