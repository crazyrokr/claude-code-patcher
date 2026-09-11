#!/usr/bin/env python3
import sys
import re

def verify_claude(filename="claude"):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Ошибка: файл {filename} не найден в текущей директории.")
        sys.exit(1)

    # Ищем функцию Hrn и извлекаем её тело
    hrn_pattern = re.compile(rb"function\s+Hrn\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)\s*\{([^}]+)\}")
    match = hrn_pattern.search(data)

    if not match:
        print("[-] Функция Hrn не найдена в бинарнике. Возможно, структура изменилась.")
        sys.exit(1)

    body = match.group(1)

    # Проверяем содержимое тела функции
    if b"999999999" in body:
        print(f"[+] Статус: ПРОПАТЧЕН УСПЕШНО")
        print(f"    Функция Hrn заменена на фиксированный бесконечный таймаут.")
        
        # Дополнительная проверка базовых констант
        if b"TQe=99999" in data:
            print(f"    Блок базовых констант (TQe/L8) также обновлен.")
        sys.exit(0)
    elif b"50000" in body or b"Math.min" in body:
        print(f"[-] Статус: НЕ ПРОПАТЧЕН (оригинальный бинарник)")
        print(f"    Обнаружена стандартная логика расчета таймаута с шагом 50000 токенов.")
        sys.exit(1)
    else:
        print(f"[?] Статус: НЕИЗВЕСТНО")
        print(f"    Тело функции Hrn отличается как от оригинала, так и от патча.")
        sys.exit(2)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "claude"
    verify_claude(target)
