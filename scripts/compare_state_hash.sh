#!/bin/sh
# TASK-002: побитное сравнение state_hash из двух JSON-отчётов.
# Использование: scripts/compare_state_hash.sh <hosted.json> <native.json>
# Выход: 0 = PASS (хешы идентичны), 1 = FAIL (расхождение), 2 = ошибка ввода.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <a.json> <b.json>" >&2
    exit 2
fi

for f in "$1" "$2"; do
    if [ ! -f "$f" ] || [ ! -r "$f" ]; then
        echo "FAIL: файл не найден или не читается: $f" >&2
        exit 2
    fi
done

extract() {
    sed -n 's/.*"state_hash"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$1"
}

# Код ошибки sed зависит от реализации (GNU=2, BSD/busybox=1) — всегда маппим в 2.
a=$(extract "$1") || exit 2
b=$(extract "$2") || exit 2

if [ -z "$a" ] || [ -z "$b" ]; then
    echo "FAIL: state_hash (64 hex) не найден в одном из файлов" >&2
    exit 2
fi

if [ "$a" = "$b" ]; then
    echo "PASS: state_hash идентичны побитно ($a)"
    exit 0
else
    echo "FAIL: state_hash расходятся" >&2
    echo "  $1: $a" >&2
    echo "  $2: $b" >&2
    exit 1
fi