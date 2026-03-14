## @file parser.py
#  @brief Разбирает файлы захвата Bluetooth (BTSnoop и PCAP).
#
#  @details Читает HCI-фреймы из файла и извлекает данные BLE-соединения,
#           параметры сопряжения SMP и информацию о ключах шифрования.
#
#           Поддерживаемые форматы:
#           - BTSnoop (RFC 1761 / Android btsnoop_hci.log)
#           - PCAP (libpcap, прямой и обратный порядок байт)
#
#  @author  RainL1
#  @version 2.0
#  @date    2026

import struct
from dataclasses import dataclass, field
from typing import Optional

## Магические байты в начале BTSnoop-файла.
BTSNOOP_MAGIC = b'btsnoop\x00'

## Поддерживается только версия 1 формата BTSnoop.
BTSNOOP_VERSION = 1


@dataclass
class SmpPairing:
    """@brief Разобранный SMP Pairing Request или Pairing Response (коды 0x01/0x02).

    @var SmpPairing.opcode              Код команды: 0x01 — Request, 0x02 — Response.
    @var SmpPairing.io_capability       Поле IO Capability.
    @var SmpPairing.oob_data            Флаг наличия OOB-данных.
    @var SmpPairing.auth_req            Битовое поле AuthReq: Bonding, MITM, SC, Keypress.
    @var SmpPairing.max_key_size        Максимальный размер ключа в байтах (7–16).
    @var SmpPairing.initiator_key_dist  Распределение ключей инициатора.
    @var SmpPairing.responder_key_dist  Распределение ключей ответчика.
    """

    opcode: int
    io_capability: int
    oob_data: int
    auth_req: int
    max_key_size: int
    initiator_key_dist: int
    responder_key_dist: int

    @property
    def mitm_protection(self) -> bool:
        """@brief True, если бит MITM (бит 2) установлен в auth_req."""
        return bool(self.auth_req & 0x04)

    @property
    def secure_connections(self) -> bool:
        """@brief True, если запрошен режим LE Secure Connections (бит 3 в auth_req)."""
        return bool(self.auth_req & 0x08)

    @property
    def bonding(self) -> bool:
        """@brief True, если запрошено связывание (биты [1:0] в auth_req ненулевые)."""
        return bool(self.auth_req & 0x03)


@dataclass
class LeConnectionInfo:
    """@brief Метаданные одного LE-соединения.

    @var LeConnectionInfo.handle               Дескриптор соединения от контроллера.
    @var LeConnectionInfo.peer_address         Адрес удалённого устройства в формате XX:XX:XX:XX:XX:XX.
    @var LeConnectionInfo.address_type         Тип адреса: 0x00 Public, 0x01 Random, 0x02/0x03 Identity.
    @var LeConnectionInfo.connection_interval  Интервал соединения (единицы 1,25 мс).
    @var LeConnectionInfo.supervision_timeout  Таймаут надзора (единицы 10 мс).
    """

    handle: int
    peer_address: str
    address_type: int
    connection_interval: int = 0
    supervision_timeout: int = 0

    @property
    def is_random_address(self) -> bool:
        """@brief True для случайного адреса (типы 0x01 и 0x03)."""
        return self.address_type in (0x01, 0x03)

    @property
    def address_type_label(self) -> str:
        """@brief Читаемое название типа адреса."""
        labels = {
            0x00: 'Public',
            0x01: 'Random',
            0x02: 'Public Identity',
            0x03: 'Random Identity',
        }
        return labels.get(self.address_type, f'Unknown({self.address_type:#04x})')


@dataclass
class EncryptionInfo:
    """@brief Состояние шифрования BLE-соединения из захвата.

    @var EncryptionInfo.enabled         True, если шифрование активно.
    @var EncryptionInfo.ltk             Байты Long-Term Key или None.
    @var EncryptionInfo.random_number   Случайное число для LTK (8 байт) или None.
    @var EncryptionInfo.ediv            Encrypted Diversifier или None.
    @var EncryptionInfo.key_size_bytes  Размер ключа в байтах или None.
    """

    enabled: bool = False
    ltk: Optional[bytes] = None
    random_number: Optional[bytes] = None
    ediv: Optional[int] = None
    key_size_bytes: Optional[int] = None

    @property
    def key_size_bits(self) -> Optional[int]:
        """@brief Размер ключа в битах или None, если неизвестен."""
        if self.key_size_bytes is not None:
            return self.key_size_bytes * 8
        if self.ltk is not None:
            return len(self.ltk) * 8
        return None

    @property
    def is_strong(self) -> bool:
        """@brief True, если размер ключа не менее 128 бит."""
        bits = self.key_size_bits
        return bits is not None and bits >= 128

    @property
    def ltk_hex(self) -> str:
        """@brief LTK в виде hex-строки в верхнем регистре или пустая строка."""
        if self.ltk:
            return self.ltk.hex().upper()
        return ''


@dataclass
class ParseResult:
    """@brief Результат разбора одного файла захвата.

    @var ParseResult.connection_type    Тип соединения: 'BLE', 'Classic Bluetooth (BR/EDR)' или 'Unknown'.
    @var ParseResult.is_ble             True, если найдены BLE-фреймы.
    @var ParseResult.is_classic_bt      True, если найдены фреймы классического Bluetooth.
    @var ParseResult.connection         Метаданные LE-соединения или None.
    @var ParseResult.pairing_request    Разобранный SMP Pairing Request или None.
    @var ParseResult.pairing_response   Разобранный SMP Pairing Response или None.
    @var ParseResult.encryption         Состояние шифрования.
    @var ParseResult.raw_records_count  Общее число HCI-записей в файле.
    @var ParseResult.errors             Список некритичных ошибок при разборе.
    """

    connection_type: str = 'Unknown'
    is_ble: bool = False
    is_classic_bt: bool = False
    connection: Optional[LeConnectionInfo] = None
    pairing_request: Optional[SmpPairing] = None
    pairing_response: Optional[SmpPairing] = None
    encryption: EncryptionInfo = field(default_factory=EncryptionInfo)
    raw_records_count: int = 0
    errors: list = field(default_factory=list)


def _parse_address(raw: bytes) -> str:
    """@brief Преобразует 6-байтовый MAC в строку вида 'AA:BB:CC:DD:EE:FF'.

    @param raw  6 байт в порядке контроллера (little-endian).
    @return     Строка адреса.
    """
    return ':'.join(f'{b:02X}' for b in reversed(raw))


def _parse_btsnoop(data: bytes) -> list:
    """@brief Разбирает BTSnoop-файл и возвращает список кортежей (flags, payload).

    @param data  Содержимое файла в байтах.
    @return      Список кортежей (flags: int, packet: bytes).
    @throws ValueError  Если файл не является BTSnoop или версия не поддерживается.
    """
    if not data.startswith(BTSNOOP_MAGIC):
        raise ValueError('Not a valid BTSnoop file')

    version = struct.unpack('>I', data[8:12])[0]
    if version != BTSNOOP_VERSION:
        raise ValueError(f'Unsupported BTSnoop version: {version}')

    records = []
    offset = 16
    while offset + 24 <= len(data):
        orig_len, incl_len, flags, drops = struct.unpack('>IIII', data[offset:offset+16])
        ts_high, ts_low = struct.unpack('>II', data[offset+16:offset+24])
        if offset + 24 + incl_len > len(data):
            break
        pkt = data[offset+24:offset+24+incl_len]
        records.append((flags, pkt))
        offset += 24 + incl_len

    return records


def _parse_btmon_packet(pkt: bytes) -> Optional[bytes]:
    """@brief Извлекает HCI-полезную нагрузку из пакета PCAP с linktype 254 (btmon).

    @param pkt  Сырые байты пакета.
    @return     Байты HCI-полезной нагрузки или None, если opcode не поддерживается.
    """
    if len(pkt) < 4:
        return None
    opcode = struct.unpack('>H', pkt[2:4])[0]
    payload = pkt[4:]
    if opcode in (0x0002, 0x0003):
        return payload
    elif opcode in (0x0004, 0x0005):
        return bytes([0x02]) + payload
    return None


def _parse_pcap(data: bytes) -> list:
    """@brief Разбирает PCAP-файл и возвращает список кортежей (flags, payload).

    @param data  Содержимое файла в байтах.
    @return      Список кортежей (flags: int, packet: bytes).
    @throws ValueError  Если файл не является корректным PCAP.
    """
    magic = struct.unpack('<I', data[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = '<'
    elif magic == 0xD4C3B2A1:
        endian = '>'
    else:
        raise ValueError('Not a valid pcap file')

    network = struct.unpack(endian + 'I', data[20:24])[0]
    is_btmon = (network == 254)

    records = []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', data[offset:offset+16])
        if offset + 16 + incl_len > len(data):
            break
        pkt = data[offset+16:offset+16+incl_len]
        if is_btmon:
            payload = _parse_btmon_packet(pkt)
            if payload is not None:
                records.append((0x02, payload))
        else:
            records.append((0x02, pkt))
        offset += 16 + incl_len

    return records


def _decode_smp(cid: int, smp_data: bytes) -> Optional[SmpPairing]:
    """@brief Декодирует SMP Pairing Request/Response из L2CAP-данных.

    @param cid       Канал L2CAP; должен быть 0x0006.
    @param smp_data  Байты начиная с кода команды SMP.
    @return          Разобранный SmpPairing или None.
    """
    if cid != 0x0006 or len(smp_data) < 7:
        return None
    opcode = smp_data[0]
    if opcode not in (0x01, 0x02):
        return None
    return SmpPairing(
        opcode=opcode,
        io_capability=smp_data[1],
        oob_data=smp_data[2],
        auth_req=smp_data[3],
        max_key_size=smp_data[4],
        initiator_key_dist=smp_data[5],
        responder_key_dist=smp_data[6],
    )


def _try_parse_l2cap(payload: bytes):
    """@brief Ищет L2CAP-фрейм внутри сырой HCI-полезной нагрузки.

    @details Перебирает до 6 смещений байт, проверяя длину L2CAP и CID.

    @param payload  Сырые байты HCI-пакета.
    @return         Кортеж (cid, smp_data) при успехе или (None, None).
    """
    for start in range(min(6, len(payload) - 4)):
        if start + 4 > len(payload):
            break
        try:
            l2cap_len = struct.unpack('<H', payload[start:start+2])[0]
            cid = struct.unpack('<H', payload[start+2:start+4])[0]
            if cid in (0x0004, 0x0006, 0x0005) and l2cap_len < 300:
                smp_data = payload[start+4:start+4+l2cap_len]
                return cid, smp_data
        except Exception:
            pass
    return None, None


def parse_capture(filepath: str) -> ParseResult:
    """@brief Разбирает файл захвата BTSnoop или PCAP.

    @details Определяет формат по магическим байтам, затем обходит все HCI-записи.
             Ошибки добавляются в ParseResult.errors без исключений.

    @param filepath  Путь к файлу захвата.
    @return          Заполненный ParseResult.
    """
    result = ParseResult()

    with open(filepath, 'rb') as f:
        data = f.read()

    try:
        if data.startswith(BTSNOOP_MAGIC):
            records = _parse_btsnoop(data)
        elif data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            records = _parse_pcap(data)
        else:
            result.errors.append('Unknown file format')
            return result
    except Exception as e:
        result.errors.append(str(e))
        return result

    result.raw_records_count = len(records)

    for flags, pkt in records:
        if len(pkt) < 3:
            continue

        _process_record(pkt, flags, result)

    if result.connection is not None:
        result.is_ble = True
        result.connection_type = 'BLE'
    elif result.encryption.ltk is not None:
        result.is_ble = True
        result.connection_type = 'BLE'

    if result.is_classic_bt and not result.is_ble:
        result.connection_type = 'Classic Bluetooth (BR/EDR)'

    _finalize_key_size(result)

    return result


def _process_record(pkt: bytes, flags: int, result: ParseResult):
    """@brief Направляет HCI-запись в нужный обработчик по первому байту пакета.

    @param pkt     Байты HCI-пакета вместе с байтом-индикатором.
    @param flags   Флаги направления BTSnoop.
    @param result  Строящийся ParseResult.
    """
    if len(pkt) < 2:
        return

    first = pkt[0]

    if first == 0x01 and len(pkt) >= 3:
        opcode = struct.unpack('<H', pkt[0:2])[0]
        _handle_hci_cmd(opcode, pkt[2:], result)
        return

    if first == 0x04 and len(pkt) >= 2:
        evt_code = pkt[1]
        _handle_hci_evt(evt_code, pkt[3:] if len(pkt) > 3 else b'', result)
        return

    if first == 0x02 and len(pkt) >= 5:
        _handle_hci_acl(pkt[1:], result)
        return

    if first == 0x19 and len(pkt) >= 3:
        opcode = struct.unpack('<H', pkt[0:2])[0]
        if opcode == 0x2019:
            _handle_le_enable_encryption(pkt[3:], result)
            return

    if first == 0x3E and len(pkt) >= 3:
        _handle_hci_evt(0x3E, pkt[2:], result)
        return

    if first == 0x08 and len(pkt) >= 5:
        if pkt[1] == 0x04:
            _handle_hci_evt(0x08, pkt[2:], result)
        return

    if first == 0x0F and len(pkt) >= 3:
        if pkt[1] == 0x04:
            opcode = struct.unpack('<H', pkt[3:5])[0] if len(pkt) >= 5 else 0
            if opcode == 0x2019:
                pass
        return

    cid, smp_data = _try_parse_l2cap(pkt)
    if cid == 0x0006 and smp_data:
        pairing = _decode_smp(cid, smp_data)
        if pairing:
            _apply_smp(pairing, result)
            return

    if len(pkt) >= 4:
        for offset in range(min(6, len(pkt) - 8)):
            if offset + 8 > len(pkt):
                break
            try:
                maybe_handle = struct.unpack('<H', pkt[offset:offset+2])[0] & 0x0FFF
                if maybe_handle == 0:
                    continue
                maybe_cid = struct.unpack('<H', pkt[offset+4:offset+6])[0]
                if maybe_cid == 0x0006:
                    smp_start = offset + 6
                    if smp_start + 1 < len(pkt):
                        smp_data_candidate = pkt[smp_start:]
                        p = _decode_smp(0x0006, smp_data_candidate)
                        if p:
                            _apply_smp(p, result)
                    break
            except Exception:
                pass


def _handle_hci_cmd(opcode: int, params: bytes, result: ParseResult):
    """@brief Обрабатывает HCI Command.

    @details Распознаёт: 0x0405 BR/EDR Create Connection, 0x2019 LE Enable Encryption,
             0x2006 LE Create Connection.

    @param opcode  16-битный код команды HCI.
    @param params  Параметры команды.
    @param result  Строящийся ParseResult.
    """
    if opcode == 0x0405:
        result.is_classic_bt = True
        if not result.is_ble:
            result.connection_type = 'Classic Bluetooth (BR/EDR)'
    elif opcode == 0x2019 and len(params) >= 26:
        _handle_le_enable_encryption(params, result)
    elif opcode == 0x2006 and len(params) >= 13:
        handle = struct.unpack('<H', params[1:3])[0]
        addr_type = params[3]
        addr_raw = params[4:10]
        addr_str = _parse_address(addr_raw)
        interval = struct.unpack('<H', params[10:12])[0] if len(params) >= 12 else 0
        result.connection = LeConnectionInfo(
            handle=handle,
            peer_address=addr_str,
            address_type=addr_type,
            connection_interval=interval,
        )
        result.is_ble = True
        result.connection_type = 'BLE'


def _handle_le_enable_encryption(params: bytes, result: ParseResult):
    """@brief Извлекает LTK из команды LE Enable Encryption (0x2019).

    @param params  Байты параметров команды.
    @param result  Строящийся ParseResult.
    """
    if len(params) < 26:
        return
    result.is_ble = True
    result.connection_type = 'BLE'
    random_num = params[2:10]
    ediv = struct.unpack('<H', params[10:12])[0]
    ltk = params[12:28]
    result.encryption.ltk = ltk
    result.encryption.random_number = random_num
    result.encryption.ediv = ediv
    result.encryption.enabled = True


def _handle_hci_evt(evt_code: int, params: bytes, result: ParseResult):
    """@brief Обрабатывает HCI Event.

    @details Распознаёт: 0x03 BR/EDR Connection Complete, 0x3E LE Meta
             (подсобытие 0x01 — LE Connection Complete), 0x08 Encryption Change.

    @param evt_code  Код события.
    @param params    Параметры события.
    @param result    Строящийся ParseResult.
    """
    if evt_code == 0x03 and len(params) >= 1:
        result.is_classic_bt = True
        if not result.is_ble:
            result.connection_type = 'Classic Bluetooth (BR/EDR)'
        return

    if evt_code == 0x3E and len(params) >= 2:
        subevent = params[0]
        if subevent == 0x01 and len(params) >= 17:
            status = params[1]
            if status != 0x00:
                return
            handle = struct.unpack('<H', params[2:4])[0] if len(params) >= 4 else 0
            role = params[4] if len(params) > 4 else 0
            addr_type = params[5] if len(params) > 5 else 0
            addr_raw = params[6:12] if len(params) >= 12 else bytes(6)
            addr_str = _parse_address(addr_raw)
            interval = struct.unpack('<H', params[12:14])[0] if len(params) >= 14 else 0
            result.connection = LeConnectionInfo(
                handle=handle,
                peer_address=addr_str,
                address_type=addr_type,
                connection_interval=interval,
            )
            result.is_ble = True
            result.connection_type = 'BLE'
    elif evt_code == 0x08 and len(params) >= 4:
        status = params[0]
        handle = struct.unpack('<H', params[1:3])[0] if len(params) >= 3 else 0
        encryption_enabled = params[3] if len(params) > 3 else 0
        if status == 0x00:
            result.encryption.enabled = bool(encryption_enabled)


def _handle_hci_acl(payload: bytes, result: ParseResult):
    """@brief Разбирает ACL Data пакет в поисках SMP PDU на канале 0x0006.

    @param payload  Байты ACL после индикатора типа пакета.
    @param result   Строящийся ParseResult.
    """
    if len(payload) < 8:
        return
    try:
        pkt_len = struct.unpack('<H', payload[2:4])[0]
        l2cap_len = struct.unpack('<H', payload[4:6])[0]
        cid = struct.unpack('<H', payload[6:8])[0]
        if cid == 0x0006:
            smp_data = payload[8:8+l2cap_len]
            pairing = _decode_smp(cid, smp_data)
            if pairing:
                _apply_smp(pairing, result)
    except Exception:
        pass


def _apply_smp(pairing: SmpPairing, result: ParseResult):
    """@brief Сохраняет SMP PDU в нужное поле ParseResult.

    @param pairing  Декодированный SmpPairing.
    @param result   Строящийся ParseResult.
    """
    result.is_ble = True
    result.connection_type = 'BLE'
    if pairing.opcode == 0x01:
        result.pairing_request = pairing
    elif pairing.opcode == 0x02:
        result.pairing_response = pairing


def _finalize_key_size(result: ParseResult):
    """@brief Определяет размер ключа из SMP PDU, если он ещё не известен.

    @details Порядок приоритета: явный key_size_bytes → max_key_size из request
             → max_key_size из response → 16 (если LTK есть).

    @param result  ParseResult для обновления.
    """
    if not result.is_ble:
        return
    if result.pairing_request and result.encryption.key_size_bytes is None:
        result.encryption.key_size_bytes = result.pairing_request.max_key_size
    if result.pairing_response and result.encryption.key_size_bytes is None:
        result.encryption.key_size_bytes = result.pairing_response.max_key_size
    if result.encryption.ltk and result.encryption.key_size_bytes is None:
        result.encryption.key_size_bytes = 16
