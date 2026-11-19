//! MAC и вывод ключей: HKDF-BLAKE3 (root_key -> epoch_key[e] -> mac_key[e,d]).
//!
//! HKDF-BLAKE3 реализован через KDF-режим BLAKE3 (blake3::derive_key):
//! контекст "veridos/epoch/{e}" / "veridos/mac/{d}", материал ключа — родительский ключ.
//! Ключи существуют только как параметры/локальные значения функций и никогда
//! не сохраняются в журнале или статических структурах.

use alloc::format;

/// Вывод ключа эпохи: epoch_key[e] = HKDF-BLAKE3(root_key, "veridos/epoch/" || e).
/// Гарантирует: детерминированность (одинаковые входы -> одинаковый ключ),
/// разделение ключей между эпохами.
pub fn epoch_key(root_key: &[u8; 32], epoch: u32) -> [u8; 32] {
    blake3::derive_key(&format!("veridos/epoch/{epoch}"), root_key)
}

/// Вывод MAC-ключа домена: mac_key[e,d] = HKDF-BLAKE3(epoch_key[e], "veridos/mac/" || d).
/// Гарантирует: детерминированность и разделение ключей между доменами одной эпохи.
pub fn mac_key(epoch_key: &[u8; 32], domain: u8) -> [u8; 32] {
    blake3::derive_key(&format!("veridos/mac/{domain}"), epoch_key)
}

/// MAC записи: первые 16 байт BLAKE3 keyed_hash(mac_key, data).
/// Гарантирует: детерминированность; data — канонический CBOR записи с нулевым mac.
pub fn compute_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let hash = blake3::keyed_hash(key, data);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&hash.as_bytes()[..16]);
    mac
}

/// Проверка MAC. Гарантирует: сравнение за константное время (без раннего выхода),
/// результат не зависит от порядка байт во времени выполнения.
pub fn verify_mac(key: &[u8; 32], data: &[u8], mac: &[u8; 16]) -> bool {
    let expected = compute_mac(key, data);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(mac.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Зануление ключевого материала после использования. Гарантирует: volatile-записи
/// не выбрасываются оптимизатором (в отличие от обычного обнуления мёртвого
/// буфера); барьер компилятора запрещает перестановку за пределы вызова.
/// Остаточный риск: внутренние копии ключа в blake3::keyed_hash/derive_key
/// crate не контролируются — зануление на стороне вызывающего обязательно.
pub fn zeroize_key(key: &mut [u8; 32]) {
    for byte in key.iter_mut() {
        // SAFETY: write_volatile в валидный выровненный байт по &mut-ссылке;
        // гонки исключены эксклюзивным заимствованием.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}