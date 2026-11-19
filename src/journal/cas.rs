//! Content-addressed storage (заглушка, in-memory).
//! Payload > 4 KB хранится в CAS, в записи остаётся только BLAKE3-хеш.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Порог inline-payload: строго больше 4096 байт уходит в CAS.
pub const THRESHOLD: usize = 4096;

/// In-memory CAS: ключ — BLAKE3-хеш содержимого (32 байта).
#[derive(Debug, Default)]
pub struct Cas {
    store: BTreeMap<[u8; 32], Vec<u8>>,
}

impl Cas {
    /// Пустое хранилище. Гарантирует: отсутствие каких-либо внешних ресурсов.
    pub fn new() -> Self {
        Self::default()
    }

    /// Кладёт данные, возвращает BLAKE3-хеш. Гарантирует: идемпотентность
    /// (повторная кладка тех же данных не меняет содержимое), адрес = хеш данных.
    pub fn put(&mut self, data: &[u8]) -> [u8; 32] {
        let hash = *blake3::hash(data).as_bytes();
        self.store.entry(hash).or_insert_with(|| data.to_vec());
        hash
    }

    /// Данные по хешу. Гарантирует: возвращает ровно те байты, что были положены
    /// под этим хешем; None, если хеш неизвестен.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.store.get(hash).map(Vec::as_slice)
    }

    /// Число объектов в хранилище.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// true, если хранилище пусто.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}