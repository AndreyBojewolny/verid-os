//! Журнал: хеш-цепочка, append/get/iter/replay/checkpoint/verify_chain.
//!
//! prev_hash[i] = BLAKE3(канонический CBOR записи[i-1]); у первой записи — нули.
//! MAC = BLAKE3 keyed(mac_key[e,d], канонический CBOR записи с нулевым mac), 16 байт.
//! Ключи передаются только параметрами функций и в журнале не хранятся.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;
use core::ops::Range;
use smallvec::{smallvec, SmallVec};

use super::cas::{Cas, THRESHOLD};
use super::cbor;
use super::mac;
use super::record::{EventKind, Record, TaintFlags};

/// Приёмник предупреждений журнала (вместо stderr; тестируется инъекцией).
pub trait WarnSink {
    /// Принимает предупреждение. Реализация не должна паниковать.
    fn warn(&mut self, message: &str);
}

/// Ошибка append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendError {
    /// causality ссылается на несуществующую запись.
    UnknownParent(u64),
    /// Validate от актора, не потребившего цель (нет записи с тем же actor
    /// и causality, содержащим seq цели). Снять UNVALIDATED может только получатель.
    NotRecipient(u64),
}

/// Ошибка verify_chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Диапазон выходит за пределы журнала.
    OutOfRange,
    /// seq записи не совпадает с её позицией.
    SeqMismatch { seq: u64 },
    /// prev_hash не совпадает с BLAKE3 предыдущей записи.
    PrevHashMismatch { seq: u64 },
    /// MAC записи невалиден для ключа её эпохи/домена.
    MacMismatch { seq: u64 },
    /// Журнал не совпадает с внешним якорем (длина, tip_hash или state_hash) —
    /// усечение, перестановка или расхождение состояния.
    AnchorMismatch,
}

/// Ошибка replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// start_seq больше длины журнала.
    OutOfRange,
}

/// Ключ дедупликации: (domain, source_seq, actor, kind, BLAKE3(payload до CAS)).
type DedupKey = (u8, u64, u64, u8, [u8; 32]);

/// Внешний якорь целостности журнала: вызывающий L0 хранит его ОТДЕЛЬНО от
/// журнала (persistence-этап) и сверяет через verify_anchor — это обнаруживает
/// усечение хвоста и перестановку, невидимые для самосогласованной цепочки.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub len: u64,
    pub tip_hash: [u8; 32],
    pub state_hash: [u8; 32],
}

/// Детерминированная модель состояния, восстанавливаемая replay.
/// state_hash — BLAKE3 от фиксированной big-endian кодировки всех полей,
/// включая цепочный аккумулятор (порядок и содержание записей влияют на хеш).
#[derive(Debug)]
struct Model {
    applied: u64,
    last_seq: u64,
    taint_acc: TaintFlags,
    kind_counts: SmallVec<[u64; 16]>,
    domain_counts: BTreeMap<u8, u64>,
    validated: BTreeSet<u64>,
    chain_acc: [u8; 32],
}

impl Default for Model {
    fn default() -> Self {
        Self {
            applied: 0,
            last_seq: 0,
            taint_acc: TaintFlags::empty(),
            kind_counts: smallvec![0u64; 16],
            domain_counts: BTreeMap::new(),
            validated: BTreeSet::new(),
            chain_acc: [0; 32],
        }
    }
}

impl Model {
    fn apply(&mut self, rec: &Record) {
        self.applied += 1;
        self.last_seq = rec.seq;
        self.taint_acc |= rec.taint;
        self.kind_counts[rec.kind.as_u8() as usize] += 1;
        *self.domain_counts.entry(rec.domain).or_insert(0) += 1;
        if rec.kind == EventKind::Validate {
            self.validated.extend(rec.causality.iter().copied());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.chain_acc);
        hasher.update(&cbor::encode(rec));
        self.chain_acc = *hasher.finalize().as_bytes();
    }

    fn state_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"veridos/state/v1");
        hasher.update(&self.last_seq.to_be_bytes());
        hasher.update(&self.applied.to_be_bytes());
        hasher.update(&self.taint_acc.bits().to_be_bytes());
        for count in &self.kind_counts {
            hasher.update(&count.to_be_bytes());
        }
        for (&domain, &count) in &self.domain_counts {
            hasher.update(&[domain]);
            hasher.update(&count.to_be_bytes());
        }
        for &seq in &self.validated {
            hasher.update(&seq.to_be_bytes());
        }
        hasher.update(&self.chain_acc);
        *hasher.finalize().as_bytes()
    }
}

/// Детерминированный журнал записей Record с криптографической целостностью.
pub struct Journal {
    records: Vec<Record>,
    cas: Cas,
    model: Model,
    seen: BTreeMap<DedupKey, u64>,
    sink: Option<Box<dyn WarnSink>>,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    /// Пустой журнал. Гарантирует: без ключей, без внешних ресурсов, sink выключен.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            cas: Cas::new(),
            model: Model::default(),
            seen: BTreeMap::new(),
            sink: None,
        }
    }

    /// Инъекция приёмника предупреждений (замена stderr).
    /// Гарантирует: предупреждения идут только в sink; без sink журнал молчит.
    pub fn set_sink(&mut self, sink: Box<dyn WarnSink>) {
        self.sink = Some(sink);
    }

    /// Атомарно добавляет запись: назначает seq, наследует taint по OR родителей,
    /// переносит payload > 4 KB в CAS, пересчитывает prev_hash и MAC.
    /// Гарантирует: служебные флаги VALIDATED/REPLAYED из taint источника
    /// маскируются (VALIDATED ставит только операция Validate, REPLAYED —
    /// только append_replayed); Validate принимается лишь от актора, уже
    /// потребившего цель (иначе NotRecipient); идемпотентность — повторная
    /// доставка того же события (domain, source_seq, actor, kind, payload)
    /// возвращает прежний seq и не меняет состояние; запись либо целиком
    /// применена, либо журнал не тронут (ошибки возможны только до мутации).
    /// Ключ mac_key — только параметр.
    pub fn append(&mut self, rec: Record, mac_key: &[u8; 32]) -> Result<u64, AppendError> {
        self.append_inner(rec, mac_key, false)
    }

    /// Вход механики replay L0: добавляет событие, помеченное REPLAYED.
    /// Гарантирует: флаг REPLAYED назначает журнал, а не источник; запись
    /// не создаёт побочных эффектов (sink молчит); прочие правила append
    /// (маскирование флагов, авторизация Validate, дедупликация) сохраняются.
    pub fn append_replayed(&mut self, rec: Record, mac_key: &[u8; 32]) -> Result<u64, AppendError> {
        self.append_inner(rec, mac_key, true)
    }

    fn append_inner(
        &mut self,
        mut rec: Record,
        mac_key: &[u8; 32],
        replayed: bool,
    ) -> Result<u64, AppendError> {
        let dedup: DedupKey = (
            rec.domain,
            rec.source_seq,
            rec.actor,
            rec.kind.as_u8(),
            *blake3::hash(&rec.payload).as_bytes(),
        );
        if let Some(&seq) = self.seen.get(&dedup) {
            return Ok(seq);
        }

        let mut taint = rec.taint;
        taint.remove(TaintFlags::VALIDATED | TaintFlags::REPLAYED);
        for &parent in &rec.causality {
            let parent_rec = usize::try_from(parent)
                .ok()
                .and_then(|index| self.records.get(index))
                .ok_or(AppendError::UnknownParent(parent))?;
            taint |= parent_rec.taint;
        }
        if rec.kind == EventKind::Validate {
            for &target in &rec.causality {
                let consumed = self
                    .records
                    .iter()
                    .any(|r| r.actor == rec.actor && r.causality.contains(&target));
                if !consumed {
                    return Err(AppendError::NotRecipient(target));
                }
            }
            taint.remove(TaintFlags::UNVALIDATED);
            taint.insert(TaintFlags::VALIDATED);
        }
        if replayed {
            taint.insert(TaintFlags::REPLAYED);
        }
        rec.taint = taint;

        if rec.payload.len() > THRESHOLD {
            let hash = self.cas.put(&rec.payload);
            rec.payload = hash.to_vec();
        }

        let seq = self.records.len() as u64;
        rec.seq = seq;
        rec.prev_hash = match self.records.last() {
            Some(last) => *blake3::hash(&cbor::encode(last)).as_bytes(),
            None => [0; 32],
        };
        rec.mac = [0; 16];
        let unsigned = cbor::encode(&rec);
        rec.mac = mac::compute_mac(mac_key, &unsigned);

        self.model.apply(&rec);
        if !rec.taint.contains(TaintFlags::REPLAYED) && rec.taint.intersects(TaintFlags::DANGEROUS) {
            if let Some(sink) = &mut self.sink {
                sink.warn(&format!(
                    "journal: tainted record seq={} kind={:?} taint={:?}",
                    seq, rec.kind, rec.taint
                ));
            }
        }
        self.records.push(rec);
        self.seen.insert(dedup, seq);
        Ok(seq)
    }

    /// Запись по seq (копия). Гарантирует: None, если seq вне журнала;
    /// корректно и на 32-битных таргетах (без усечения u64 -> usize).
    pub fn get(&self, seq: u64) -> Option<Record> {
        let index = usize::try_from(seq).ok()?;
        self.records.get(index).cloned()
    }

    /// Итератор по записям в порядке seq.
    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.records.iter()
    }

    /// Число записей.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// true, если журнал пуст.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Восстанавливает детерминированную модель, применяя записи с start_seq
    /// к пустой модели. Гарантирует: state_hash после replay(0) совпадает с
    /// текущим; события с taint REPLAYED не создают побочных эффектов (sink
    /// при replay не вызывается никогда). Записи и CAS не изменяются.
    pub fn replay(&mut self, start_seq: u64) -> Result<(), ReplayError> {
        if start_seq > self.records.len() as u64 {
            return Err(ReplayError::OutOfRange);
        }
        self.model = Model::default();
        for rec in &self.records[start_seq as usize..] {
            self.model.apply(rec);
        }
        Ok(())
    }

    /// Фиксирует состояние: добавляет запись Checkpoint с payload = state_hash
    /// модели на момент вызова и возвращает её. Гарантирует: детерминированность
    /// state_hash; checkpoint сам входит в журнал и учитывается последующим replay.
    pub fn checkpoint(&mut self, epoch: u32, mac_key: &[u8; 32]) -> Result<Record, AppendError> {
        let state_hash = self.model.state_hash();
        let rec = Record::draft(
            epoch,
            0,
            self.records.len() as u64,
            0,
            EventKind::Checkpoint,
            TaintFlags::empty(),
            Vec::new(),
            state_hash.to_vec(),
        );
        let seq = self.append(rec, mac_key)?;
        Ok(self.records[seq as usize].clone())
    }

    /// Проверка цепочки и MAC записей в диапазоне по ключам их эпох
    /// (epoch_key/mac_key выводятся из root_key на лету, не хранятся).
    /// Гарантирует: обнаруживает подмену любого байта любой записи диапазона
    /// (через MAC или prev_hash следующей записи); порядок проверок — по seq.
    pub fn verify_chain(&self, range: Range<u64>, root_key: &[u8; 32]) -> Result<(), VerifyError> {
        if range.start > range.end || range.end > self.records.len() as u64 {
            return Err(VerifyError::OutOfRange);
        }
        for seq in range.start..range.end {
            let rec = &self.records[seq as usize];
            if rec.seq != seq {
                return Err(VerifyError::SeqMismatch { seq });
            }
            let expected_prev = if seq == 0 {
                [0; 32]
            } else {
                *blake3::hash(&cbor::encode(&self.records[(seq - 1) as usize])).as_bytes()
            };
            if rec.prev_hash != expected_prev {
                return Err(VerifyError::PrevHashMismatch { seq });
            }
            let mut epoch_key = mac::epoch_key(root_key, rec.epoch);
            let mut mac_key = mac::mac_key(&epoch_key, rec.domain);
            let mut unsigned = rec.clone();
            unsigned.mac = [0; 16];
            let mac_ok = mac::verify_mac(&mac_key, &cbor::encode(&unsigned), &rec.mac);
            mac::zeroize_key(&mut epoch_key);
            mac::zeroize_key(&mut mac_key);
            if !mac_ok {
                return Err(VerifyError::MacMismatch { seq });
            }
        }
        Ok(())
    }

    /// state_hash текущей детерминированной модели.
    /// Гарантирует: детерминированность; совпадает после replay(0).
    pub fn state_hash(&self) -> [u8; 32] {
        self.model.state_hash()
    }

    /// Снимок внешнего якоря: длина, BLAKE3 канонического CBOR последней записи
    /// (нули для пустого журнала) и state_hash модели. Гарантирует:
    /// детерминированность; вызывающий хранит якорь отдельно от журнала.
    pub fn anchor(&self) -> Anchor {
        Anchor {
            len: self.records.len() as u64,
            tip_hash: match self.records.last() {
                Some(last) => *blake3::hash(&cbor::encode(last)).as_bytes(),
                None => [0; 32],
            },
            state_hash: self.model.state_hash(),
        }
    }

    /// Сверка журнала с внешним якорем. Гарантирует: обнаруживает усечение
    /// хвоста, перестановку и любое расхождение длины/состояния/последней
    /// записи (AnchorMismatch); не заменяет verify_chain, а дополняет его.
    pub fn verify_anchor(&self, anchor: &Anchor) -> Result<(), VerifyError> {
        if self.anchor() == *anchor {
            Ok(())
        } else {
            Err(VerifyError::AnchorMismatch)
        }
    }

    /// Доступ к CAS журнала (чтение данных, вынесенных из payload).
    pub fn cas(&self) -> &Cas {
        &self.cas
    }

    /// Сборка журнала из готовых записей БЕЗ проверки цепочки и MAC.
    /// Гарантирует: модель и индекс дедупликации восстанавливаются по записям;
    /// целостность не проверяется — для тестов и восстановления, вызывающий
    /// обязан сам вызвать verify_chain.
    pub fn from_records_unchecked(records: Vec<Record>, cas: Cas) -> Self {
        let mut journal = Self {
            records,
            cas,
            model: Model::default(),
            seen: BTreeMap::new(),
            sink: None,
        };
        for rec in &journal.records {
            journal.model.apply(rec);
            let dedup: DedupKey = (
                rec.domain,
                rec.source_seq,
                rec.actor,
                rec.kind.as_u8(),
                *blake3::hash(&rec.payload).as_bytes(),
            );
            journal.seen.insert(dedup, rec.seq);
        }
        journal
    }
}