#!/usr/bin/env python3
import sys
import re

def patch_claude(filename="claude"):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Ошибка: файл {filename} не найден в текущей директории.")
        sys.exit(1)

    modified_data = data
    success_count = 0

    # 1. Поиск и замена функции Hrn с автоматическим выравниванием байтовой длины (паддингом пробелами)
    hrn_pattern = re.compile(rb"function\s+Hrn\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)\s*\{[^}]+\}")
    match_hrn = hrn_pattern.search(modified_data)

    if match_hrn:
        old_func = match_hrn.group(0)
        new_func_core = b"function Hrn(e){return 999999999;}"
        
        if len(new_func_core) > len(old_func):
            print("Ошибка: новая версия функции длиннее оригинала.")
        else:
            # Заполняем остаток пробелами перед закрывающей фигурной скобкой для точного совпадения байт
            padding_needed = len(old_func) - len(new_func_core)
            new_func = new_func_core[:-1] + b" " * padding_needed + b"}"
            
            if len(old_func) != len(new_func):
                print("Ошибка безопасности: несовпадение байтовой длины при паддинге!")
                sys.exit(1)
                
            modified_data = modified_data.replace(old_func, new_func)
            print(f"[+] Функция Hrn успешно пропатчена (заменена на бесконечный таймаут, длина: {len(old_func)} байт).")
            success_count += 1
    else:
        print("[-] Функция Hrn не найдена по шаблону.")

    # 2. Дополнительное обновление базовых констант таймаута (TQe, L8, Lrn), если они присутствуют
    const_pattern = re.compile(
        rb"([a-zA-Z_$][a-zA-Z0-9_$]*=)60000,\s*([a-zA-Z_$][a-zA-Z0-9_$]*=)120000,\s*([a-zA-Z_$][a-zA-Z0-9_$]*=)60000"
    )
    match_const = const_pattern.search(modified_data)
    if match_const:
        old_block = match_const.group(0)
        new_block = old_block.replace(b"60000", b"99999").replace(b"120000", b"999999")
        if len(old_block) == len(new_block):
            modified_data = modified_data.replace(old_block, new_block)
            print(f"[+] Блок базовых констант успешно обновлен байт-в-байт.")
            success_count += 1

    if success_count > 0:
        output_filename = filename + ".patched"
        with open(output_filename, "wb") as f:
            f.write(modified_data)
        print(f"\nГотово! Создан пропатченный файл: {output_filename}")
        print(f"Примените его командами:")
        print(f"  mv {output_filename} {filename}")
        print(f"  chmod +x {filename}")
    else:
        print("\nНи один патч не был применен: структура бинарника отличается от ожидаемой.")
        sys.exit(1)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "claude"
    patch_claude(target)
