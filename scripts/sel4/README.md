# Процедура нативного прогона diff-тестов (этап B, seL4 userland)

Цель: побитно сравнить state_hash сценария diff-v1 на hosted и на нативе.
Расхождение = FAIL (нарушение детерминизма).

## Предусловия

1. Ядро журнала no_std+alloc (проверено hosted-сборкой; кросс-компиляция — шаг 2).
2. Генератор сценария diff-v1 сейчас живёт в tests/diff_state_hash.rs (std-тест).
   Для нативного прогона его нужно вынести в общий no_std-модуль
   (отдельный brief с расширением зоны на src/ — вне зоны TASK-002).
   Константы сценария (N=1200, ROOT=[7;32], epoch/300, domain%3, actor%5,
   payload i%5000, Validate+потребление, checkpoint/200, replayed/100)
   должны совпадать бит-в-бит.
3. Нативный harness: no_std-бинарь без libc; ограниченный stdout через
   seL4 debug-syscall (или semihosting на отладочных платформах) — только
   вывод hex state_hash/.tip_hash, без форматирования времени/адресов.

## Шаги

1. Установить таргет платформы:
   `rustup target add thumbv7em-none-eabihf` (ARMv7-M)
   или `rustup target add aarch64-unknown-none` (AArch64).
2. Скопировать `scripts/sel4/cargo-config.toml` в `.cargo/config.toml`
   (или использовать `--target <таргет>` явно). Проверка ядра:
   `cargo build --release --lib` — должно собраться без std.
3. Собрать нативный harness этапа B с общим генератором diff-v1;
   прошить/загрузить образ на платформу seL4.
4. Прогнать сценарий: >=1000 записей, verify_chain, replay(0), state_hash.
   Снять hex по ограниченному stdout и оформить JSON той же схемы
   `veridos/state-hash/v1` в `reports/state_hash_native.json`:
   `{ "schema", "scenario": "diff-v1", "target": "sel4-<платформа>",
     "records", "state_hash", "tip_hash" }`.
5. Сравнить побитно:
   `sh scripts/compare_state_hash.sh reports/state_hash.json reports/state_hash_native.json`
   Выход 0 = PASS; 1 = FAIL (расхождение хешей); 2 = ошибка ввода.
6. Зафиксировать результат в отчёте VERIFIER этапа B; при FAIL — остановить
   интеграцию, разобрать расхождение (порядок байт, выравнивание, usize-касты,
   версии крейтов — первые кандидаты).

## Регрессионный вектор diff-v1 (hosted)

- records: 1293
- state_hash: `7b0be0df33077c8e7996a6f476209e33e473e5dae38759a56f04e1fa08aebc32`
- Зафиксирован: reports/state_hash.json; встроен в tests/diff_state_hash.rs
  (EXPECTED_STATE_HASH) — любой прогон на hosted сверяется автоматически.

## Замечания

- blake3/ciborium собираются с default-features = false (no_std); на нативе
  использовать те же версии крейтов (Cargo.lock) — иначе детерминизм не гарантирован.
- usize-касты в ядре защищены try_from/диапазонами (аудит TASK-005, Minor-3/6):
  на 32-битном нативе поведение идентично hosted.
- Версии крейтов и флаги компиляции (-C opt-level, panic=abort) не влияют на
  результат BLAKE3/CBOR, но влияют на паники — harness должен обрабатывать
  ошибки append без unwrap-паник в релизе.