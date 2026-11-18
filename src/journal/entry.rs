//! Упрощённое ядро журнала: JournalEntry + append с taint-флагом.

/// Запись журнала.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub timestamp: u64,
    pub event_type: String,
    pub payload: String,
    pub taint_flag: bool,
}

impl JournalEntry {
    /// Создаёт запись; гарантирует сохранность всех переданных полей без изменений.
    pub fn new(timestamp: u64, event_type: impl Into<String>, payload: impl Into<String>, taint_flag: bool) -> Self {
        Self {
            timestamp,
            event_type: event_type.into(),
            payload: payload.into(),
            taint_flag,
        }
    }
}

/// Журнал: упорядоченный список записей.
#[derive(Debug, Default)]
pub struct Journal {
    entries: Vec<JournalEntry>,
}

impl Journal {
    /// Создаёт пустой журнал.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет запись; гарантирует, что запись никогда не блокируется,
    /// порядок записей совпадает с порядком вызовов, taint_flag сохраняется.
    /// При taint_flag == true выводит предупреждение, но запись принимается.
    pub fn append(&mut self, entry: JournalEntry) {
        if entry.taint_flag {
            eprintln!(
                "[WARN] suspicious journal entry: event_type={} timestamp={} taint_flag=true",
                entry.event_type, entry.timestamp
            );
        }
        self.entries.push(entry);
    }

    /// Возвращает все записи в порядке добавления.
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// Количество записей в журнале.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// true, если журнал пуст.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}