# Спецификация: детерминированный журнал VeridOS v0.1

## Формат записи
```rust
pub struct Record {
    pub seq: u64,                 // глобальный порядок, назначает только L0
    pub epoch: u32,               // эпоха ключей
    pub domain: u8,               // 0=L0, 1=L1, 2=L2, 16+=клетки
    pub source_seq: u64,          // локальный счётчик источника
    pub causality: Vec<u64>,      // ссылки на родительские записи
    pub actor: u64,               // capability актора
    pub kind: EventKind,          // 16 видов событий
    pub taint: TaintFlags,        // 9 бит, наследуется по OR
    pub payload: Vec<u8>,         // канонический CBOR; >4KB -> BLAKE3-хеш
    pub prev_hash: [u8; 32],      // BLAKE3(запись[i-1])
    pub mac: [u8; 16],            // BLAKE3 keyed, 16 байт
}
```

## EventKind (16 значений, закрытый словарь)
CapGrant, CapRevoke, McpRequest, McpResponse, AgentDecision, Validate,
Quarantine, DlqEntry, Checkpoint, EpochRotate, TaintApply, ReplayEvent,
TaskStart, TaskEnd, CellSpawn, CellHalt.

## TaintFlags (9 бит)
EXTERNAL_NET, LLM_OUTPUT, L2_UNTRUSTED, UNVALIDATED, QUARANTINED,
VALIDATED, EPOCH_REVOKED, DLQ, REPLAYED.
Наследование: taint(ребёнка) = OR(taint родителей) | флаг источника.
Снять UNVALIDATED может только получатель — операцией Validate (запись в журнал).

## Криптография и ключи
- root_key (32 байта) — офлайн.
- epoch_key[e] = HKDF-BLAKE3(root_key, "veridos/epoch/" || e)
- mac_key[e,d] = HKDF-BLAKE3(epoch_key[e], "veridos/mac/" || domain)
- Ключи существуют только в L0. Capability на ключ не существует по построению.

## Операции журнала
- append(record) -> SeqNo — пересчёт prev_hash и MAC, атомарно.
- get(seq) -> Option<Record>
- iter() -> итератор по seq
- replay(start_seq) — применение событий к детерминированной модели;
  события с taint REPLAYED не создают побочных эффектов.
- checkpoint() -> Record с state_hash модели.
- verify_chain(range) — проверка prev_hash и MAC по ключу эпохи записи.

## Открытые решения (за владельцем)
1. Хранение root_key: passphrase или Shamir.
2. Политика ротации эпох: по времени / по числу записей / по сигналу.
3. Политика чистки и архивации Content-CAS.

## Критерии готовности модуля
- Канонический CBOR бит-в-бит на всех платформах.
- 100% replay.
- Мутационные тесты: подмена любой байт-позиции обнаруживается.
