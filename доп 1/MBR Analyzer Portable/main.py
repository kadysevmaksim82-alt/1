import struct
import os
import sys
from datetime import datetime
import json
import yaml

def clear_screen():
    """Очистка экрана консоли"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Вывод заголовка программы"""
    print("╔══════════════════════════════════════════════════════════╗")
    print("║              АНАЛИЗАТОР MBR / ЗАГРУЗОЧНЫХ СЕКТОРОВ       ║")
    print("║                     v1.0 - 2025                          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

def get_file_path():
    """Запрос пути к файлу с проверкой"""
    while True:
        print("Введите путь к файлу дампа MBR:")
        print("(Пример: C:/Users/Имя/Downloads/backup.bin или /home/user/dump.bin)")
        print("Для выхода введите 'q' или 'exit'")
        print()

        file_path = input(">>> ").strip().strip('"').strip("'")

        # Проверка на выход
        if file_path.lower() in ['q', 'exit', 'quit', 'выход']:
            print("\nВыход из программы...")
            sys.exit(0)

        # Проверка существования файла
        if not os.path.exists(file_path):
            print(f"\n ОШИБКА: Файл '{file_path}' не найден!")
            print("Проверьте правильность пути и повторите ввод.\n")
            continue

        # Проверка размера файла
        file_size = os.path.getsize(file_path)
        if file_size < 512:
            print(f"\n⚠ ПРЕДУПРЕЖДЕНИЕ: Файл слишком мал ({file_size} байт).")
            print("Для анализа MBR нужен файл размером не менее 512 байт.")

            choice = input("Продолжить анализ? (y/n): ").lower()
            if choice != 'y':
                continue

        return file_path

def load_file_data(file_path):
    """Загрузка данных из файла"""
    try:
        with open(file_path, 'rb') as f:
            # Читаем первые 512 байт (стандартный размер MBR)
            data = f.read(512)

        print(f"✓ Файл загружен: {os.path.basename(file_path)}")
        print(f"✓ Размер прочитанных данных: {len(data)} байт")
        return data

    except Exception as e:
        print(f" ОШИБКА при чтении файла: {e}")
        return None

def parse_mbr_complete(data):
    """Полный парсинг всех 512 байт MBR"""
    if len(data) < 512:
        return {"error": f"Некорректный размер MBR: {len(data)} байт (должно быть не менее 512)"}

    # Если данных больше 512 байт, берем только первые 512
    if len(data) > 512:
        data = data[:512]
        print(f"⚠ Внимание: файл больше 512 байт. Анализируются первые 512 байт.")

    result = {
        "filename": os.path.basename(file_path),
        "full_path": file_path,
        "size": len(data),
        "timestamp": datetime.now().isoformat(),
        "sections": {}
    }

    # 1. Загрузочный код (первые 446 байт)
    boot_code = data[:446]
    result["sections"]["boot_code"] = {
        "offset": "0x000-0x1BD",
        "size": 446,
        "hex_preview": ' '.join(f'{b:02X}' for b in boot_code[:32]),
        "contains_data": any(b != 0 for b in boot_code),
        "analysis": parse_boot_code(boot_code)
    }

    # 2. Таблица разделов (64 байта)
    partition_table = data[446:510]
    result["sections"]["partition_table"] = {
        "offset": "0x1BE-0x1FD",
        "size": 64,
        "partitions": parse_partition_table(partition_table)
    }

    # 3. Сигнатура (последние 2 байта)
    signature = data[510:512]
    result["sections"]["signature"] = {
        "offset": "0x1FE-0x1FF",
        "size": 2,
        "hex": f"0x{signature[0]:02X} 0x{signature[1]:02X}",
        "valid": signature == b'\x55\xAA',
        "analysis": parse_signature(signature)
    }

    # 4. HEX-дамп всего MBR
    result["hex_dump"] = create_hex_dump(data)

    # 5. Дополнительная информация
    result["statistics"] = calculate_statistics(result)

    return result

def parse_boot_code(boot_code):
    """Анализ загрузочного кода"""
    analysis = []

    # Проверяем, пустой ли код
    is_empty = all(b == 0 for b in boot_code)

    if is_empty:
        analysis.append("Загрузочный код: ОТСУТСТВУЕТ (все байты равны 0)")
        analysis.append("Это означает, что MBR не содержит кода загрузчика")
        analysis.append("  Возможные причины: чистый диск, поврежденный MBR, GPT диск")
    else:
        analysis.append("Загрузочный код: ПРИСУТСТВУЕТ")

        # Ищем известные загрузчики
        if boot_code[:5] == b'\xEB\x63\x90\x4D\x53':  # Windows MBR
            analysis.append(" Обнаружен: Windows MBR (стандартный)")
        elif boot_code[:3] == b'\xFA\xFC\x31':  # GRUB
            analysis.append(" Обнаружен: GRUB загрузчик (сигнатура)")
        elif b'GRUB' in boot_code or b'grub' in boot_code:
            analysis.append(" Обнаружен: GRUB загрузчик")
        elif b'LILO' in boot_code:
            analysis.append(" Обнаружен: LILO загрузчик")
        elif boot_code[:2] == b'\xEB\x3C':  # MS-DOS
            analysis.append(" Обнаружен: MS-DOS загрузчик")
        else:
            analysis.append(" Тип загрузчика: Неизвестный или пользовательский")

        # Ищем строки в коде
        strings = extract_strings(boot_code)
        if strings:
            analysis.append(f" Обнаружены строки: {', '.join(strings[:3])}")

        # Проверяем на наличие кода
        opcode_count = sum(1 for b in boot_code if b in [0x90, 0x00, 0xFF, 0xEB, 0xE9])  # NOP, ADD, JMP
        if opcode_count > 100:
            analysis.append(f" Обнаружен исполняемый код (около {opcode_count} инструкций)")

    # Статистика
    zero_bytes = sum(1 for b in boot_code if b == 0)
    analysis.append(f" Статистика: {zero_bytes}/446 нулевых байтов ({zero_bytes / 446 * 100:.1f}%)")

    return analysis

def parse_partition_table(table_data):
    """Анализ таблицы разделов (4 записи по 16 байт)"""
    partitions = []

    partition_types = {
        0x00: "Пусто", 0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended",
        0x06: "FAT16", 0x07: "NTFS/exFAT/HPFS", 0x0B: "FAT32",
        0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)",
        0x82: "Linux swap", 0x83: "Linux", 0x85: "Linux extended",
        0x8E: "Linux LVM", 0xFD: "Linux RAID", 0xEF: "EFI System",
        0xEE: "GPT Protective", 0xFF: "BBT",
        0x11: "Hidden FAT12", 0x14: "Hidden FAT16 <32M",
        0x16: "Hidden FAT16", 0x1B: "Hidden FAT32",
        0x1C: "Hidden FAT32 (LBA)", 0x1E: "Hidden FAT16 (LBA)"
    }

    for i in range(4):
        offset = i * 16
        entry = table_data[offset:offset + 16]

        partition = {
            "index": i + 1,
            "offset_hex": f"0x{446 + offset:03X}",
            "offset_dec": 446 + offset,
            "raw_hex": ' '.join(f'{b:02X}' for b in entry)
        }

        # Проверяем, пустая ли запись
        if entry[0] == 0 and entry[4] == 0:
            partition["status"] = "Пустой"
            partition["analysis"] = [" Запись свободна"]
        else:
            # Парсим данные раздела
            try:
                bootable = entry[0]
                type_code = entry[4]
                lba_start = struct.unpack('<I', entry[8:12])[0]
                sectors = struct.unpack('<I', entry[12:16])[0]

                partition["status"] = "Заполнен"
                partition["bootable"] = bootable == 0x80
                partition["type_code"] = f"0x{type_code:02X}"
                partition["type_name"] = partition_types.get(type_code, "Неизвестный")
                partition["lba_start"] = lba_start
                partition["sectors"] = sectors
                partition["size_bytes"] = sectors * 512
                partition["size_mb"] = (sectors * 512) / (1024 * 1024)
                partition["size_gb"] = partition["size_mb"] / 1024

                analysis = []
                analysis.append(f" Активен: {'ДА' if partition['bootable'] else 'нет'}")
                analysis.append(f" Тип: {partition['type_name']} ({partition['type_code']})")
                analysis.append(f" Начальный сектор: {lba_start}")
                analysis.append(f" Секторов: {sectors:,}")
                analysis.append(f" Размер: {partition['size_mb']:.2f} MB ({partition['size_gb']:.3f} GB)")

                # Проверка на корректность
                if sectors == 0:
                    analysis.append(" Внимание: размер раздела равен 0")
                if lba_start < 63 and lba_start != 0:
                    analysis.append(" Внимание: нестандартное начало раздела")

                partition["analysis"] = analysis

            except Exception as e:
                partition["status"] = "Ошибка"
                partition["analysis"] = [f" Ошибка разбора: {e}"]

        partitions.append(partition)

    return partitions

def parse_signature(signature):
    """Анализ сигнатуры"""
    analysis = []
    b1, b2 = signature[0], signature[1]

    analysis.append(f" Байт 1 (0x1FE): 0x{b1:02X} = {b1:08b} бинарный")
    analysis.append(f" Байт 2 (0x1FF): 0x{b2:02X} = {b2:08b} бинарный")

    if b1 == 0x55 and b2 == 0xAA:
        analysis.append(" ✓ СИГНАТУРА КОРРЕКТНА: 0x55 0xAA")
        analysis.append("   BIOS распознает этот сектор как загрузочный")
    else:
        analysis.append("  СИГНАТУРА НЕКОРРЕКТНА: ожидается 0x55 0xAA")
        if b1 != 0x55:
            analysis.append(f"Байт 1 должен быть 0x55, а не 0x{b1:02X}")
        if b2 != 0xAA:
            analysis.append(f" Байт 2 должен быть 0xAA, а не 0x{b2:02X}")

        # Возможные альтернативные сигнатуры
        if b1 == 0xAA and b2 == 0x55:
            analysis.append("  Обнаружена обратная сигнатура (AA 55)")

    return analysis

def extract_strings(data, min_len=4):
    """Извлекает строки из бинарных данных"""
    strings = []
    current = []

    for byte in data:
        if 32 <= byte <= 126:  # Печатные ASCII символы
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []

    if len(current) >= min_len:
        strings.append(''.join(current))

    return strings

def create_hex_dump(data):
    """Создает полный HEX-дамп MBR"""
    dump = []

    for i in range(0, 512, 16):
        offset = i
        hex_bytes = ' '.join(f'{b:02X}' for b in data[i:i + 16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i + 16])

        # Определяем секцию для подсветки
        section = ""
        if i < 446:
            section = "Загрузочный код"
        elif i < 510:
            section = "Таблица разделов"
        elif i >= 510:
            section = "Сигнатура"

        dump.append({
            "offset": f"0x{i:03X}",
            "offset_dec": i,
            "hex": hex_bytes,
            "ascii": ascii_part,
            "section": section
        })

    return dump

def calculate_statistics(result):
    """Вычисление статистики"""
    stats = {}

    # Статистика по загрузочному коду
    boot_code_info = result["sections"]["boot_code"]
    stats["boot_code_has_data"] = boot_code_info["contains_data"]

    # Статистика по разделам
    partitions = result["sections"]["partition_table"]["partitions"]
    empty_count = sum(1 for p in partitions if p["status"] == "Пустой")
    active_count = sum(1 for p in partitions if p.get("bootable", False))
    gpt_count = sum(1 for p in partitions if p.get("type_code") == "0xEE")

    stats["partitions_total"] = 4
    stats["partitions_used"] = 4 - empty_count
    stats["partitions_empty"] = empty_count
    stats["partitions_active"] = active_count
    stats["partitions_gpt"] = gpt_count

    # Общая статистика
    stats["signature_valid"] = result["sections"]["signature"]["valid"]

    # Определение типа диска
    if gpt_count > 0:
        stats["disk_type"] = "GPT (с защитной MBR)"
    elif empty_count == 4:
        stats["disk_type"] = "Пустой диск"
    else:
        stats["disk_type"] = "MBR диск"

    return stats

def print_mbr_analysis(result):
    """Выводит результаты анализа в читаемом виде"""
    clear_screen()

    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                     РЕЗУЛЬТАТЫ АНАЛИЗА MBR                        ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()

    print("─" * 70)
    print(" ОБЩАЯ ИНФОРМАЦИЯ")
    print("─" * 70)
    print(f" Файл: {result['filename']}")
    print(f" Путь: {result['full_path']}")
    print(f" Размер: {result['size']} байт")
    print(f" Время анализа: {result['timestamp']}")
    print()

    # Тип диска
    disk_type = result["statistics"]["disk_type"]
    print(f" Тип диска: {disk_type}")

    # 1. Загрузочный код
    print()
    print("─" * 70)
    print(" ЗАГРУЗОЧНЫЙ КОД (446 байт, 0x000-0x1BD)")
    print("─" * 70)
    boot_info = result["sections"]["boot_code"]
    for line in boot_info["analysis"]:
        print(f" {line}")
    print(f" HEX-просмотр: {boot_info['hex_preview']}...")

    # 2. Таблица разделов
    print()
    print("─" * 70)
    print(" ТАБЛИЦА РАЗДЕЛОВ (64 байта, 0x1BE-0x1FD)")
    print("─" * 70)
    partitions = result["sections"]["partition_table"]["partitions"]

    # Статистика разделов
    empty_count = result["statistics"]["partitions_empty"]
    active_count = result["statistics"]["partitions_active"]

    print(f" Статистика: {4 - empty_count}/4 заполненных, {active_count} активных")
    print()

    for partition in partitions:
        status_icon = "" if partition["status"] == "Заполнен" else "○"
        boot_icon = "" if partition.get("bootable", False) else " "

        print(f" {status_icon}{boot_icon} РАЗДЕЛ {partition['index']} (смещение {partition['offset_hex']}):")
        print(f"   HEX: {partition['raw_hex']}")

        if "analysis" in partition:
            for line in partition["analysis"]:
                print(f"   {line}")
        print()

    # 3. Сигнатура
    print("─" * 70)
    print(" СИГНАТУРА MBR (2 байта, 0x1FE-0x1FF)")
    print("─" * 70)
    sig_info = result["sections"]["signature"]
    print(f" HEX: {sig_info['hex']}")
    for line in sig_info["analysis"]:
        print(f" {line}")

    # 4. Полный HEX-дамп (опционально)
    print()
    print("─" * 70)
    print(" HEX-ДАМП MBR (первые 128 байт)")
    print("─" * 70)
    print(" Смещение  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII")
    print(" ─" * 60)

    for i, line in enumerate(result["hex_dump"][:8]):  # Показываем первые 8 строк (128 байт)
        section_marker = ""
        if line["section"] == "Таблица разделов" and i % 4 == 0:
            section_marker = f" ← Раздел {i // 4 - 27 + 1}"
        elif line["section"] == "Сигнатура":
            section_marker = " ← SIGNATURE"

        print(f" {line['offset']}  {line['hex']:<47}  {line['ascii']}{section_marker}")

    # 5. Итоговая информация
    print()
    print("─" * 70)
    print(" ИТОГОВЫЙ АНАЛИЗ")
    print("─" * 70)

    issues = []
    warnings = []

    # Проверка целостности MBR
    if not boot_info["contains_data"]:
        issues.append("Загрузочный код отсутствует")

    if empty_count == 4:
        issues.append("Таблица разделов пустая")

    if not sig_info["valid"]:
        issues.append("Сигнатура MBR некорректна")

    # Предупреждения
    gpt_count = result["statistics"]["partitions_gpt"]
    if gpt_count > 0:
        warnings.append("Обнаружен GPT protective partition - это GPT диск")

    if active_count > 1:
        warnings.append("Несколько активных разделов - может вызвать проблемы с загрузкой")

    # Вывод результатов проверок
    if not issues:
        print("  MBR имеет корректную структуру")
        print(" Все проверки пройдены успешно")
    else:
        print("  Обнаружены проблемы:")
        for issue in issues:
            print(f"   • {issue}")

    if warnings:
        print()
        print(" ⚠ Предупреждения:")
        for warning in warnings:
            print(f"   • {warning}")

    # Структура MBR
    print()
    print("  Структура MBR:")
    print(f"   • Загрузочный код: 446 байт (87.1%)")
    print(f"   • Таблица разделов: 64 байта (12.5%)")
    print(f"   • Сигнатура: 2 байта (0.4%)")
    print(f"   • Всего: 512 байт (100%)")

    # Меню действий после анализа
    print()
    print("─" * 70)
    print(" ДОПОЛНИТЕЛЬНЫЕ ДЕЙСТВИЯ")
    print("─" * 70)
    print(" 1. Показать полный HEX-дамп (512 байт)")
    print(" 2. Сохранить отчет в файл")
    print(" 3. Проанализировать другой файл")
    print(" 4. Выход из программы")
    print()

def show_full_hex_dump(result):
    """Показать полный HEX-дамп"""
    clear_screen()

    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                     ПОЛНЫЙ HEX-ДАМП MBR (512 байт)                ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()

    print(" Смещение  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII     Секция")
    print(" ─" * 70)

    for line in result["hex_dump"]:
        section_abbr = ""
        if line["section"] == "Загрузочный код":
            section_abbr = "BOOT"
        elif line["section"] == "Таблица разделов":
            # Определяем номер раздела
            offset_dec = line["offset_dec"]
            if 446 <= offset_dec < 462:
                section_abbr = "PART1"
            elif 462 <= offset_dec < 478:
                section_abbr = "PART2"
            elif 478 <= offset_dec < 494:
                section_abbr = "PART3"
            elif 494 <= offset_dec < 510:
                section_abbr = "PART4"
        elif line["section"] == "Сигнатура":
            section_abbr = "SIGN"

        print(f" {line['offset']}  {line['hex']:<47}  {line['ascii']}   {section_abbr}")

    print()
    input("Нажмите Enter для возврата в меню...")

def save_report(result):
    """Сохранение отчета в файл"""
    print()
    print("─" * 70)
    print(" СОХРАНЕНИЕ ОТЧЕТА")
    print("─" * 70)

    # Предлагаем варианты сохранения
    print("Выберите формат сохранения:")
    print(" 1. Текстовый файл (.txt)")
    print(" 2. JSON файл (.json)")
    print(" 3. YAML файл (.yaml)")
    print(" 0. Отмена")
    print()

    choice = input("Ваш выбор: ").strip()

    if choice == "0":
        print("Сохранение отменено.")
        return

    # Генерация имени файла по умолчанию
    base_name = os.path.splitext(result["filename"])[0]
    default_name = f"mbr_analysis_{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if choice == "1":
        ext = ".txt"
        file_content = format_text_report(result)
    elif choice == "2":
        ext = ".json"
        file_content = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    elif choice == "3":
        ext = ".yaml"
        file_content = yaml.dump(result, allow_unicode=True, default_flow_style=False)
    else:
        print(" Неверный выбор.")
        return

    # Запрос имени файла
    print()
    print(f"Введите имя файла (по умолчанию: {default_name}{ext}):")
    file_name = input(">>> ").strip()

    if not file_name:
        file_name = default_name + ext
    elif not file_name.endswith(ext):
        file_name += ext

    try:
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(file_content)

        print(f" Отчет успешно сохранен в файл: {file_name}")
        print(f"   Полный путь: {os.path.abspath(file_name)}")

    except Exception as e:
        print(f" Ошибка при сохранении файла: {e}")

def format_text_report(result):
    """Форматирование текстового отчета"""
    lines = []

    lines.append("=" * 70)
    lines.append("АНАЛИЗ MBR - ОТЧЕТ")
    lines.append("=" * 70)
    lines.append(f"Файл: {result['filename']}")
    lines.append(f"Полный путь: {result['full_path']}")
    lines.append(f"Размер: {result['size']} байт")
    lines.append(f"Время анализа: {result['timestamp']}")
    lines.append()

    # Загрузочный код
    lines.append("=" * 70)
    lines.append("1. ЗАГРУЗОЧНЫЙ КОД")
    lines.append("=" * 70)
    boot_info = result["sections"]["boot_code"]
    for line in boot_info["analysis"]:
        lines.append(line)

    # Таблица разделов
    lines.append()
    lines.append("=" * 70)
    lines.append("2. ТАБЛИЦА РАЗДЕЛОВ")
    lines.append("=" * 70)
    for partition in result["sections"]["partition_table"]["partitions"]:
        lines.append(f"Раздел {partition['index']}:")
        if "analysis" in partition:
            for line in partition["analysis"]:
                lines.append(f"  {line}")
        lines.append()

    # Сигнатура
    lines.append("=" * 70)
    lines.append("3. СИГНАТУРА")
    lines.append("=" * 70)
    sig_info = result["sections"]["signature"]
    for line in sig_info["analysis"]:
        lines.append(line)

    # HEX-дамп
    lines.append()
    lines.append("=" * 70)
    lines.append("4. ПОЛНЫЙ HEX-ДАМП")
    lines.append("=" * 70)
    for line in result["hex_dump"]:
        lines.append(f"{line['offset']}: {line['hex']}  {line['ascii']}")

    # Статистика
    lines.append()
    lines.append("=" * 70)
    lines.append("5. СТАТИСТИКА")
    lines.append("=" * 70)
    stats = result["statistics"]
    lines.append(f"Тип диска: {stats['disk_type']}")
    lines.append(f"Разделов использовано: {stats['partitions_used']}/4")
    lines.append(f"Активных разделов: {stats['partitions_active']}")
    lines.append(f"Сигнатура корректна: {'Да' if stats['signature_valid'] else 'Нет'}")
    lines.append(f"Загрузочный код присутствует: {'Да' if stats['boot_code_has_data'] else 'Нет'}")

    return '\n'.join(lines)

def main_menu(result):
    """Главное меню после анализа"""
    while True:
        choice = input("Выберите действие (1-4): ").strip()

        if choice == "1":
            show_full_hex_dump(result)
            print_mbr_analysis(result)  # Возвращаемся к основному выводу
        elif choice == "2":
            save_report(result)
            print_mbr_analysis(result)
        elif choice == "3":
            return True  # Сигнализируем о необходимости анализа нового файла
        elif choice == "4":
            print("\nВыход из программы...")
            sys.exit(0)
        else:
            print(" Неверный выбор. Попробуйте снова.")

# Основной цикл программы
if __name__ == "__main__":
    while True:
        clear_screen()
        print_header()

        # Запрос пути к файлу
        file_path = get_file_path()

        # Загрузка и анализ файла
        data = load_file_data(file_path)
        if data is None:
            print("\nНе удалось загрузить файл. Попробуйте еще раз.")
            input("Нажмите Enter для продолжения...")
            continue

        print("\nАнализирую MBR структуру...")

        # Парсинг MBR
        result = parse_mbr_complete(data)

        if "error" in result:
            print(f" Ошибка анализа: {result['error']}")
            input("Нажмите Enter для продолжения...")
            continue

        # Вывод результатов
        print_mbr_analysis(result)

        # Обработка действий пользователя
        need_new_file = main_menu(result)
        if not need_new_file:
            break