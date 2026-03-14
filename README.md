# BLEGuard — Анализатор безопасности Bluetooth BLE

Программное обеспечение для анализа безопасности Bluetooth-соединений в режиме BLE.  
Реализует проверку ключа шифрования, типа соединения, MAC-адреса и других параметров безопасности.

---

## Установка

### Зависимости

```bash
pip install PyQt5
```

Для захвата трафика:

```bash
# Arch Linux
sudo pacman -S wireshark-qt

# Kali / Debian / Ubuntu
sudo apt install tshark

# macOS
brew install wireshark
```

### Запуск

```bash
cd bleguard
python3 main.py
```

---

## Использование

1. Нажмите **«Начать захват»** — приложение запускает захват Bluetooth-трафика.
2. Подключите Bluetooth/BLE-устройство к компьютеру.
3. Нажмите **«Проверить соединение»** — приложение проанализирует захваченный трафик.

Для демонстрации и тестирования:  
Используйте **«Загрузить дамп»** и откройте один из файлов в папке `bleguard/tests/`.

---

## Тестовые дампы

| Файл | Описание | Ожидаемый результат |
|------|----------|---------------------|
| `test_01_ble_strong_key.btsnoop` | BLE, LTK 128 бит | OK / Предупреждение (статический MAC) |
| `test_02_ble_weak_7byte_key.btsnoop` | BLE, ключ 56 бит (KNOB-уязвимость) | **КРИТИЧНО** |
| `test_03_ble_no_encryption.btsnoop` | BLE, нет шифрования | **КРИТИЧНО** |
| `test_04_ble_static_mac.btsnoop` | BLE, статичный MAC | Предупреждение |
| `test_05_ble_random_mac.btsnoop` | BLE, случайный MAC | OK |
| `test_06_ble_mitm_protection.btsnoop` | BLE, MITM-защита включена | OK |
| `test_07_ble_extremely_weak_key.btsnoop` | BLE, ключ 8 бит | **КРИТИЧНО** |
| `test_08_ble_secure_connections.btsnoop` | BLE, LE Secure Connections | OK |
| `test_09_ble_borderline_key.btsnoop` | BLE, ключ 72 бит | Предупреждение |
| `test_10_ble_encryption_disabled.btsnoop` | BLE, шифрование отключено | **КРИТИЧНО** |
| `test_11_real_capture_ltk128bit.btsnoop` | Реальный Wireshark-дамп, LTK=128 бит | Предупреждение |
| `test_12_ble_just_works_no_mitm.btsnoop` | BLE, Just Works (без MITM) | Предупреждение |

---

## Запуск тестов

```bash
cd bleguard
python3 -m bleguard.tests.run_tests
# или
PYTHONPATH=. python3 bleguard/tests/run_tests.py
```

---

## Архитектура

```
bleguard/
├── main.py                  # Точка входа
└── bleguard/
    ├── core/
    │   ├── parser.py        # Парсинг BTSnoop/PCAP, HCI, SMP пакетов
    │   ├── analyzer.py      # Анализ безопасности, формирование выводов
    │   └── capture.py       # Управление живым захватом (tshark)
    ├── gui/
    │   ├── main_window.py   # PyQt5 GUI
    │   └── i18n.py          # Перевод RU/EN
    └── tests/
        ├── generate_test_dumps.py  # Генератор тестовых дампов
        ├── run_tests.py            # Тест-раннер (12 тестов)
        └── test_*.btsnoop          # Тестовые BTSnoop-файлы
```

---

## Поддерживаемые форматы

- BTSnoop (`.btsnoop`) — формат Linux Bluetooth monitor
- PCAP (`.pcap`) — стандартный Wireshark/tcpdump формат

---

## Поддерживаемые ОС

- Linux (Arch, Kali, Ubuntu, Astra Linux)
- macOS
- Windows
