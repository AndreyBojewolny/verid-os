# VeridOS — стартовый пакет v2.5

Пакет для запуска мультиагентной разработки в QwenWork (десктопный агент).

## Структура
- QWEN.md — мастер-правила проекта (подхватывается агентом автоматически)
- SKILL.md — общий контракт разработки
- specs/ — спецификации (единственный источник истины)
- docs/constitution_v2.5_changelog.md — изменения конституции v2.4 -> v2.5
- agents/ — роли (SKILL.md каждой роли; загружать в QwenWork как Skills)
- workflows/ — пайплайн
- tasks/ — task brief'ы (TASK-001..004), запускать строго по очереди
- src/, tests/ — скелет кода с TODO-заглушками

## Порядок запуска
1. Распаковать, git init, коммит в main.
2. Загрузить роли из agents/ как Skills (Extensions -> Skills -> Upload).
3. Задача 1: вставить текст tasks/TASK-001-journal-core.brief,
   дописать: «Выполняй в роли IMPLEMENTER, следуй agents/IMPLEMENTER.SKILL.md.
   По завершении создай отчёт reports/implementer-journal-core.md».
4. Приёмка Архитектором: отчёт в reports/, git diff vs specs/, локальный cargo build && cargo test.
5. Далее по очереди: VERIFIER -> AUDITOR -> (решение владельца) -> INTEGRATOR.

## Правило дисциплины
Одна задача = один brief = один запуск. Не давать агенту «сделай всё сразу».
