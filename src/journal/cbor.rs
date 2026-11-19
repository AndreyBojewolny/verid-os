//! Канонический CBOR для Record (RFC 7049 canonical): бит-в-бит на всех платформах.
//!
//! Правила канона: map из 11 полей с ключами, отсортированными по длине затем
//! лексикографически; целые — кратчайшей формой; payload/prev_hash/mac — byte
//! strings; causality — массив uint; kind/taint — uint. Порядок ключей фиксирован
//! и не зависит от платформы или версии крейта.

use alloc::vec::Vec;
use ciborium::value::Value;

use super::record::{EventKind, Record, TaintFlags};

/// Ошибка разбора канонического CBOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborError {
    /// Синтаксическая ошибка CBOR-потока.
    Syntax,
    /// Поток валиден, но не является канонической записью журнала
    /// (не map из 11 полей, неверные типы/длины, неизвестные kind/taint).
    Shape,
}

/// Сериализация записи в канонический CBOR. Гарантирует: детерминированный
/// результат бит-в-бит для одинаковых полей; ошибок не бывает (запись в Vec).
pub fn encode(rec: &Record) -> Vec<u8> {
    let entries = alloc::vec![
        (Value::Text("mac".into()), Value::Bytes(rec.mac.to_vec())),
        (Value::Text("seq".into()), Value::Integer(rec.seq.into())),
        (Value::Text("kind".into()), Value::Integer((rec.kind.as_u8() as u64).into())),
        (Value::Text("actor".into()), Value::Integer(rec.actor.into())),
        (Value::Text("epoch".into()), Value::Integer((rec.epoch as u64).into())),
        (Value::Text("taint".into()), Value::Integer((rec.taint.bits() as u64).into())),
        (Value::Text("domain".into()), Value::Integer((rec.domain as u64).into())),
        (Value::Text("payload".into()), Value::Bytes(rec.payload.clone())),
        (
            Value::Text("causality".into()),
            Value::Array(rec.causality.iter().map(|&s| Value::Integer(s.into())).collect()),
        ),
        (Value::Text("prev_hash".into()), Value::Bytes(rec.prev_hash.to_vec())),
        (Value::Text("source_seq".into()), Value::Integer(rec.source_seq.into())),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
        .expect("запись CBOR в Vec не может завершиться ошибкой ввода-вывода");
    buf
}

/// Разбор канонического CBOR в запись. Гарантирует: принимает только map ровно
/// из 11 известных полей с ожидаемыми типами и длинами; закрытые словари
/// EventKind (0..=20) и TaintFlags (9 бит) проверяются, иначе CborError::Shape.
pub fn decode(bytes: &[u8]) -> Result<Record, CborError> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CborError::Syntax)?;
    let map = match value {
        Value::Map(map) if map.len() == 11 => map,
        _ => return Err(CborError::Shape),
    };

    let mac: [u8; 16] = bytes_field(&map, "mac")?.try_into().map_err(|_| CborError::Shape)?;
    let prev_hash: [u8; 32] = bytes_field(&map, "prev_hash")?
        .try_into()
        .map_err(|_| CborError::Shape)?;
    let kind_code = uint_field(&map, "kind")?;
    let kind = EventKind::from_u8(u8::try_from(kind_code).map_err(|_| CborError::Shape)?)
        .ok_or(CborError::Shape)?;
    let taint_bits = uint_field(&map, "taint")?;
    let taint = TaintFlags::from_bits(u16::try_from(taint_bits).map_err(|_| CborError::Shape)?)
        .ok_or(CborError::Shape)?;
    let causality = match field(&map, "causality")? {
        Value::Array(items) => items
            .iter()
            .map(|item| to_u64(item))
            .collect::<Result<Vec<u64>, CborError>>()?,
        _ => return Err(CborError::Shape),
    };

    Ok(Record {
        seq: uint_field(&map, "seq")?,
        epoch: u32::try_from(uint_field(&map, "epoch")?).map_err(|_| CborError::Shape)?,
        domain: u8::try_from(uint_field(&map, "domain")?).map_err(|_| CborError::Shape)?,
        source_seq: uint_field(&map, "source_seq")?,
        causality,
        actor: uint_field(&map, "actor")?,
        kind,
        taint,
        payload: bytes_field(&map, "payload")?,
        prev_hash,
        mac,
    })
}

fn field<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a Value, CborError> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .map(|(_, v)| v)
        .ok_or(CborError::Shape)
}

fn to_u64(value: &Value) -> Result<u64, CborError> {
    match value {
        Value::Integer(i) => u64::try_from(i128::from(*i)).map_err(|_| CborError::Shape),
        _ => Err(CborError::Shape),
    }
}

fn uint_field(map: &[(Value, Value)], key: &str) -> Result<u64, CborError> {
    to_u64(field(map, key)?)
}

fn bytes_field(map: &[(Value, Value)], key: &str) -> Result<Vec<u8>, CborError> {
    match field(map, key)? {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(CborError::Shape),
    }
}