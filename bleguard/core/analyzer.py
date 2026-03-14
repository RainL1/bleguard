## @file analyzer.py
#  @brief Анализирует безопасность BLE-захвата и строит отчёт.
#
#  @details Принимает ParseResult от parser.py, проверяет ключевые параметры
#           безопасности и возвращает SecurityReport с выводами и метриками.
#
#  @author  RainL1
#  @version 2.0
#  @date    2026

from dataclasses import dataclass, field
from typing import List, Optional
from .parser import ParseResult


def _t(key: str) -> str:
    from ..gui.i18n import t
    return t(key)

## @defgroup уровни_риска Уровни риска
#  @{

## Всё в порядке, проблем нет.
RISK_OK = 'ok'

## Есть слабое место, стоит обратить внимание.
RISK_WARN = 'warn'

## Критическая уязвимость, нужно действовать сразу.
RISK_CRITICAL = 'critical'

## Информационная заметка, на безопасность не влияет.
RISK_INFO = 'info'

## @}

## Минимальный рекомендуемый размер ключа в байтах (128 бит).
MIN_KEY_SIZE_BYTES = 16

## Ниже этого порога в байтах ключ считается критически слабым (56 бит).
WARN_KEY_SIZE_BYTES = 8


@dataclass
class SecurityFinding:
    """@brief Один вывод безопасности с заголовком и описанием на двух языках.

    @var SecurityFinding.level      Уровень риска: RISK_OK / RISK_INFO / RISK_WARN / RISK_CRITICAL.
    @var SecurityFinding.title_ru   Заголовок на русском.
    @var SecurityFinding.title_en   Заголовок на английском.
    @var SecurityFinding.detail_ru  Описание и рекомендации на русском.
    @var SecurityFinding.detail_en  Описание и рекомендации на английском.
    """

    level: str
    title_ru: str
    title_en: str
    detail_ru: str
    detail_en: str


@dataclass
class SecurityReport:
    """@brief Итоговый отчёт по одному файлу захвата.

    @var SecurityReport.connection_type  Тип соединения: 'BLE', 'Classic BR/EDR' и т.д.
    @var SecurityReport.is_ble           True, если в захвате есть BLE-фреймы.
    @var SecurityReport.overall_risk     Наихудший уровень риска среди всех выводов.
    @var SecurityReport.findings         Список выводов SecurityFinding.
    @var SecurityReport.metrics          Метрики для таблицы GUI: ключ → (метка, значение, риск).
    """

    connection_type: str
    is_ble: bool
    overall_risk: str
    findings: List[SecurityFinding] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def add(self, level: str, title_ru: str, title_en: str, detail_ru: str, detail_en: str):
        """@brief Добавляет вывод в отчёт.

        @param level      Уровень риска.
        @param title_ru   Заголовок на русском.
        @param title_en   Заголовок на английском.
        @param detail_ru  Описание на русском.
        @param detail_en  Описание на английском.
        """
        self.findings.append(SecurityFinding(level, title_ru, title_en, detail_ru, detail_en))

    def elevate_risk(self, level: str):
        """@brief Повышает общий риск, если переданный уровень серьёзнее текущего.

        @param level  Кандидат нового уровня риска.
        """
        order = [RISK_OK, RISK_INFO, RISK_WARN, RISK_CRITICAL]
        if order.index(level) > order.index(self.overall_risk):
            self.overall_risk = level


def analyze(result: ParseResult) -> SecurityReport:
    """@brief Проверяет безопасность захвата и возвращает отчёт.

    @details Для BLE проверяет: тип MAC-адреса, шифрование, длину ключа,
             флаг MITM и режим сопряжения. Для классического Bluetooth —
             только информационная заметка.

    @param result  Заполненный ParseResult из parse_capture().
    @return        SecurityReport со всеми выводами и метриками.
    """
    report = SecurityReport(
        connection_type=result.connection_type,
        is_ble=result.is_ble,
        overall_risk=RISK_OK,
    )

    if not result.is_ble:
        if result.is_classic_bt:
            report.add(
                RISK_INFO,
                'Классическое Bluetooth-соединение (BR/EDR)',
                'Classic Bluetooth connection (BR/EDR)',
                'Захвачено классическое Bluetooth-соединение. Анализ BLE-параметров недоступен. '
                'Классический Bluetooth имеет собственный профиль безопасности.',
                'A Classic Bluetooth (BR/EDR) connection was captured. '
                'BLE-specific analysis is not applicable. '
                'Classic Bluetooth uses a different security profile.',
            )
            report.metrics['connection_type'] = (_t('metric_connection_type'), 'Classic BR/EDR', RISK_INFO)
        else:
            report.add(
                RISK_INFO,
                'BLE-соединение не обнаружено',
                'No BLE connection detected',
                'В захваченном трафике не найдено ни одного BLE-соединения. '
                'Убедитесь, что устройство подключалось во время захвата, и повторите попытку.',
                'No BLE connection was found in the captured traffic. '
                'Make sure the device was paired during the capture and try again.',
            )
            report.metrics['connection_type'] = (_t('metric_connection_type'), _t('val_not_detected'), RISK_INFO)
            report.metrics['packets_analyzed'] = (_t('metric_packets'), str(result.raw_records_count), RISK_INFO)
        report.elevate_risk(RISK_INFO)
        return report

    conn = result.connection
    enc = result.encryption
    pairing_req = result.pairing_request
    pairing_resp = result.pairing_response

    if conn:
        addr_label = conn.address_type_label
        if conn.is_random_address:
            report.add(
                RISK_OK,
                'Случайный MAC-адрес',
                'Randomized MAC address',
                f'Устройство использует случайный MAC-адрес ({conn.peer_address}), '
                'что затрудняет отслеживание устройства злоумышленником.',
                f'The device uses a randomized MAC address ({conn.peer_address}), '
                'which makes tracking harder for an attacker.',
            )
            report.metrics['mac_address'] = (
                _t('metric_mac_address'),
                f'{conn.peer_address} (Random — {addr_label})',
                RISK_OK,
            )
        else:
            report.add(
                RISK_WARN,
                'Статический MAC-адрес',
                'Static MAC address',
                f'Устройство использует статический публичный MAC-адрес ({conn.peer_address}). '
                'Злоумышленник может отслеживать устройство по фиксированному идентификатору.',
                f'The device uses a static public MAC address ({conn.peer_address}). '
                'An attacker can track the device using this fixed identifier.',
            )
            report.metrics['mac_address'] = (
                _t('metric_mac_address'),
                f'{conn.peer_address} (Static — {addr_label})',
                RISK_WARN,
            )
            report.elevate_risk(RISK_WARN)
    else:
        report.metrics['mac_address'] = (_t('metric_mac_address'), _t('val_not_found'), RISK_INFO)

    if not enc.enabled:
        report.add(
            RISK_CRITICAL,
            'Шифрование отсутствует',
            'Encryption absent',
            'В захваченном трафике не обнаружено шифрование соединения. '
            'Данные передаются в открытом виде и могут быть перехвачены пассивным наблюдателем.',
            'No encryption was detected in the captured traffic. '
            'Data is transmitted in plaintext and can be intercepted by a passive observer.',
        )
        report.metrics['encryption'] = (_t('metric_encryption'), _t('val_absent'), RISK_CRITICAL)
        report.elevate_risk(RISK_CRITICAL)
    else:
        report.add(
            RISK_OK,
            'Шифрование активно',
            'Encryption active',
            'Соединение зашифровано (LE Encryption активен).',
            'The connection is encrypted (LE Encryption is active).',
        )
        report.metrics['encryption'] = (_t('metric_encryption'), _t('val_active'), RISK_OK)

    key_bytes = enc.key_size_bytes
    if key_bytes is not None:
        key_bits = key_bytes * 8
        if key_bytes < WARN_KEY_SIZE_BYTES:
            report.add(
                RISK_CRITICAL,
                f'Критически малая длина ключа: {key_bits} бит ({key_bytes} байт)',
                f'Critically short encryption key: {key_bits} bits ({key_bytes} bytes)',
                f'Длина ключа шифрования составляет всего {key_bits} бит ({key_bytes} байт). '
                f'Рекомендуемый минимум — 128 бит (16 байт). '
                'Такой ключ уязвим к KNOB-атаке и brute-force. Необходимо переподключение.',
                f'The encryption key is only {key_bits} bits ({key_bytes} bytes). '
                f'The recommended minimum is 128 bits (16 bytes). '
                'This key is vulnerable to KNOB attacks and brute-force. Reconnect is required.',
            )
            report.metrics['key_size'] = (
                _t('metric_key_size'),
                f'{key_bits} {_t("val_bits")} ({key_bytes} {_t("val_bytes")}) — {_t("val_critical_suffix")}',
                RISK_CRITICAL,
            )
            report.elevate_risk(RISK_CRITICAL)
        elif key_bytes < MIN_KEY_SIZE_BYTES:
            report.add(
                RISK_WARN,
                f'Недостаточная длина ключа: {key_bits} бит ({key_bytes} байт)',
                f'Insufficient key length: {key_bits} bits ({key_bytes} bytes)',
                f'Длина ключа {key_bits} бит ({key_bytes} байт) ниже рекомендуемых 128 бит. '
                'Соединение потенциально уязвимо. Рекомендуется переподключение.',
                f'Key length {key_bits} bits ({key_bytes} bytes) is below the recommended 128 bits. '
                'The connection is potentially vulnerable. Reconnect is recommended.',
            )
            report.metrics['key_size'] = (
                _t('metric_key_size'),
                f'{key_bits} {_t("val_bits")} ({key_bytes} {_t("val_bytes")}) — {_t("val_warning_suffix")}',
                RISK_WARN,
            )
            report.elevate_risk(RISK_WARN)
        else:
            report.add(
                RISK_OK,
                f'Длина ключа шифрования: {key_bits} бит ({key_bytes} байт)',
                f'Encryption key length: {key_bits} bits ({key_bytes} bytes)',
                f'Ключ шифрования имеет длину {key_bits} бит ({key_bytes} байт) — соответствует рекомендуемому минимуму.',
                f'Encryption key is {key_bits} bits ({key_bytes} bytes) — meets the recommended minimum.',
            )
            report.metrics['key_size'] = (
                _t('metric_key_size'),
                f'{key_bits} {_t("val_bits")} ({key_bytes} {_t("val_bytes")})',
                RISK_OK,
            )
    else:
        report.metrics['key_size'] = (_t('metric_key_size'), _t('val_not_determined'), RISK_INFO)

    if enc.ltk:
        report.metrics['ltk'] = (
            'LTK (Long Term Key)',
            enc.ltk_hex,
            RISK_INFO,
        )

    if pairing_req or pairing_resp:
        smp = pairing_resp or pairing_req
        if smp.mitm_protection:
            report.add(
                RISK_OK,
                'Защита от MITM включена',
                'MITM protection enabled',
                'Флаг MITM (Man-in-the-Middle protection) установлен при сопряжении.',
                'The MITM (Man-in-the-Middle protection) flag was set during pairing.',
            )
            report.metrics['mitm'] = (_t('metric_mitm'), _t('val_enabled'), RISK_OK)
        else:
            report.add(
                RISK_WARN,
                'MITM-защита отключена',
                'MITM protection disabled',
                'Флаг защиты от атак Man-in-the-Middle не установлен. '
                'Режим «Just Works» не обеспечивает аутентификацию устройств.',
                'The MITM protection flag was not set during pairing. '
                '"Just Works" mode does not authenticate devices, enabling MITM attacks.',
            )
            report.metrics['mitm'] = (_t('metric_mitm'), _t('val_disabled'), RISK_WARN)
            report.elevate_risk(RISK_WARN)

        if smp.secure_connections:
            report.add(
                RISK_OK,
                'Secure Connections (LE Secure Connections)',
                'Secure Connections (LE Secure Connections)',
                'Используется режим LE Secure Connections с ECDH-обменом ключами — усиленная защита.',
                'LE Secure Connections mode with ECDH key exchange is in use — enhanced protection.',
            )
            report.metrics['secure_connections'] = (_t('metric_secure_connections'), _t('val_active'), RISK_OK)
        else:
            report.add(
                RISK_INFO,
                'LE Legacy Pairing',
                'LE Legacy Pairing',
                'Используется устаревший режим сопряжения LE Legacy Pairing. '
                'Рекомендуется использовать LE Secure Connections для лучшей защиты.',
                'LE Legacy Pairing mode is in use. '
                'LE Secure Connections is recommended for better security.',
            )
            report.metrics['secure_connections'] = (_t('metric_secure_connections'), _t('val_inactive'), RISK_INFO)

    report.metrics['connection_type'] = (_t('metric_connection_type'), 'BLE (Bluetooth Low Energy)', RISK_INFO)
    report.metrics['packets_analyzed'] = (_t('metric_packets'), str(result.raw_records_count), RISK_INFO)

    return report
