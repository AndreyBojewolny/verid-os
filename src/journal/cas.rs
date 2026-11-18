//! Content-addressed storage (заглушка, in-memory).
//! TODO(TASK-001): put_content(data) -> BLAKE3-хеш; get_content(hash) -> data.
//! Payload > 4 KB хранится как хеш.
