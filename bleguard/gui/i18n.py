## @file i18n.py
#  @brief Модуль локализации GUI BLEGuard.
#
#  @details Хранит строки интерфейса на русском и английском в словаре STRINGS.
#           Язык переключается через set_lang(), строка берётся через t().
#
#  @author  RainL1
#  @version 2.0
#  @date    2026

## Код русского языка.
LANG_RU = 'ru'

## Код английского языка.
LANG_EN = 'en'

## Текущий язык интерфейса.
_current_lang = LANG_RU

## @brief Словарь локализованных строк.
#  @details Структура: { ключ: { LANG_RU: '...', LANG_EN: '...' } }.
STRINGS = {
    'app_title': {
        LANG_RU: 'BLEGuard — Анализ безопасности Bluetooth',
        LANG_EN: 'BLEGuard — Bluetooth Security Analyzer',
    },
    'btn_start': {
        LANG_RU: 'Начать захват',
        LANG_EN: 'Start Capture',
    },
    'btn_stop': {
        LANG_RU: 'Остановить',
        LANG_EN: 'Stop',
    },
    'btn_check': {
        LANG_RU: 'Проверить соединение',
        LANG_EN: 'Check Connection',
    },
    'btn_load_file': {
        LANG_RU: 'Загрузить дамп',
        LANG_EN: 'Load Dump',
    },
    'btn_clear': {
        LANG_RU: 'Очистить',
        LANG_EN: 'Clear',
    },
    'status_idle': {
        LANG_RU: 'Ожидание',
        LANG_EN: 'Idle',
    },
    'status_capturing': {
        LANG_RU: 'Захват трафика активен... Подключите BLE-устройство',
        LANG_EN: 'Capture active... Connect your BLE device now',
    },
    'status_ready_to_check': {
        LANG_RU: 'Захват остановлен. Нажмите «Проверить соединение»',
        LANG_EN: 'Capture stopped. Press "Check Connection"',
    },
    'status_analyzing': {
        LANG_RU: 'Анализ трафика...',
        LANG_EN: 'Analyzing traffic...',
    },
    'status_done': {
        LANG_RU: 'Анализ завершён',
        LANG_EN: 'Analysis complete',
    },
    'step1': {
        LANG_RU: '1. Нажмите «Начать захват»',
        LANG_EN: '1. Press «Start Capture»',
    },
    'step2': {
        LANG_RU: '2. Подключите Bluetooth-устройство к компьютеру',
        LANG_EN: '2. Connect your Bluetooth device to the computer',
    },
    'step3': {
        LANG_RU: '3. Нажмите «Проверить соединение»',
        LANG_EN: '3. Press «Check Connection»',
    },
    'section_metrics': {
        LANG_RU: 'Метрики безопасности',
        LANG_EN: 'Security Metrics',
    },
    'section_findings': {
        LANG_RU: 'Выводы анализа',
        LANG_EN: 'Analysis Findings',
    },
    'overall_safe': {
        LANG_RU: 'Соединение безопасно',
        LANG_EN: 'Connection is secure',
    },
    'overall_info': {
        LANG_RU: 'Нет данных для анализа',
        LANG_EN: 'No data to analyze',
    },
    'overall_warn': {
        LANG_RU: 'Есть предупреждения',
        LANG_EN: 'Warnings detected',
    },
    'overall_critical': {
        LANG_RU: 'Критические уязвимости',
        LANG_EN: 'Critical vulnerabilities',
    },
    'reconnect_advice': {
        LANG_RU: 'Рекомендуется переподключить устройство для смены ключа шифрования',
        LANG_EN: 'Reconnecting the device is recommended to rotate the encryption key',
    },
    'file_dialog_title': {
        LANG_RU: 'Открыть файл захвата',
        LANG_EN: 'Open capture file',
    },
    'no_data': {
        LANG_RU: 'Данные не получены. Запустите захват или загрузите файл.',
        LANG_EN: 'No data captured. Start capture or load a file.',
    },
    'classic_connection': {
        LANG_RU: 'Классическое Bluetooth-соединение (BR/EDR)',
        LANG_EN: 'Classic Bluetooth Connection (BR/EDR)',
    },
    'ble_connection': {
        LANG_RU: 'BLE-соединение',
        LANG_EN: 'BLE Connection',
    },
    'tshark_missing': {
        LANG_RU: 'tshark не найден. Используйте «Загрузить дамп» для анализа файла.',
        LANG_EN: 'tshark not found. Use "Load Dump" to analyze a file.',
    },
    'capturing_hint': {
        LANG_RU: 'Захват запущен. Теперь подключите Bluetooth-устройство к компьютеру, затем нажмите «Проверить соединение».',
        LANG_EN: 'Capture started. Now connect your Bluetooth device to the computer, then press "Check Connection".',
    },
    'mode_live': {
        LANG_RU: 'Режим: живой захват',
        LANG_EN: 'Mode: live capture',
    },
    'mode_file': {
        LANG_RU: 'Режим: анализ файла',
        LANG_EN: 'Mode: file analysis',
    },
    'loaded_file': {
        LANG_RU: 'Файл загружен',
        LANG_EN: 'File loaded',
    },
    'metric_connection_type': {
        LANG_RU: 'Тип соединения',
        LANG_EN: 'Connection type',
    },
    'metric_mac_address': {
        LANG_RU: 'MAC-адрес',
        LANG_EN: 'MAC address',
    },
    'metric_encryption': {
        LANG_RU: 'Шифрование',
        LANG_EN: 'Encryption',
    },
    'metric_key_size': {
        LANG_RU: 'Длина ключа',
        LANG_EN: 'Key size',
    },
    'metric_mitm': {
        LANG_RU: 'MITM-защита',
        LANG_EN: 'MITM protection',
    },
    'metric_secure_connections': {
        LANG_RU: 'Secure Connections',
        LANG_EN: 'Secure Connections',
    },
    'metric_packets': {
        LANG_RU: 'Пакетов проанализировано',
        LANG_EN: 'Packets analyzed',
    },
    'val_active': {
        LANG_RU: 'Активно',
        LANG_EN: 'Active',
    },
    'val_absent': {
        LANG_RU: 'Отсутствует',
        LANG_EN: 'Absent',
    },
    'val_enabled': {
        LANG_RU: 'Включена',
        LANG_EN: 'Enabled',
    },
    'val_disabled': {
        LANG_RU: 'Отключена',
        LANG_EN: 'Disabled',
    },
    'val_inactive': {
        LANG_RU: 'Не активно',
        LANG_EN: 'Inactive',
    },
    'val_not_found': {
        LANG_RU: 'Не обнаружен',
        LANG_EN: 'Not found',
    },
    'val_not_determined': {
        LANG_RU: 'Не определена',
        LANG_EN: 'Not determined',
    },
    'val_not_detected': {
        LANG_RU: 'Не обнаружено',
        LANG_EN: 'Not detected',
    },
    'val_critical_suffix': {
        LANG_RU: 'КРИТИЧНО',
        LANG_EN: 'CRITICAL',
    },
    'val_warning_suffix': {
        LANG_RU: 'ПРЕДУПРЕЖДЕНИЕ',
        LANG_EN: 'WARNING',
    },
    'val_bits': {
        LANG_RU: 'бит',
        LANG_EN: 'bits',
    },
    'val_bytes': {
        LANG_RU: 'байт',
        LANG_EN: 'bytes',
    },
    'how_to_use': {
        LANG_RU: 'КАК ИСПОЛЬЗОВАТЬ',
        LANG_EN: 'HOW TO USE',
    },
}


def set_lang(lang: str):
    """@brief Устанавливает язык интерфейса.

    @param lang  Код языка: LANG_RU ('ru') или LANG_EN ('en').
    """
    global _current_lang
    if lang in (LANG_RU, LANG_EN):
        _current_lang = lang


def get_lang() -> str:
    """@brief Возвращает текущий язык интерфейса.

    @return Строка 'ru' или 'en'.
    """
    return _current_lang


def t(key: str) -> str:
    """@brief Возвращает переведённую строку по ключу.

    @details Порядок: текущий язык → английский → сам ключ как заглушка.

    @param key  Ключ из словаря STRINGS.
    @return     Локализованная строка.
    """
    entry = STRINGS.get(key, {})
    return entry.get(_current_lang, entry.get(LANG_EN, key))
