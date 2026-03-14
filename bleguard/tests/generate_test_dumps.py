import struct
import os
import time

BTSNOOP_MAGIC = b'btsnoop\x00'
BTSNOOP_VERSION = 1
BTSNOOP_DATALINK_HCI = 1002

EPOCH_DIFF = 122192928000000000
BASE_TS = int(time.time() * 1e6) * 10 + EPOCH_DIFF


def btsnoop_header():
    return BTSNOOP_MAGIC + struct.pack('>II', BTSNOOP_VERSION, BTSNOOP_DATALINK_HCI)


def btsnoop_record(data: bytes, flags: int, ts_offset_us: int = 0) -> bytes:
    ts = BASE_TS + ts_offset_us * 10
    ts_high = (ts >> 32) & 0xFFFFFFFF
    ts_low = ts & 0xFFFFFFFF
    length = len(data)
    return struct.pack('>IIIIII', length, length, flags, 0, ts_high, ts_low) + data


def hci_cmd(opcode: int, params: bytes) -> bytes:
    return struct.pack('<HB', opcode, len(params)) + params


def hci_evt(event_code: int, params: bytes) -> bytes:
    return struct.pack('<BB', event_code, len(params)) + params


def hci_acl(handle: int, cid: int, l2cap_data: bytes) -> bytes:
    l2cap = struct.pack('<HH', len(l2cap_data), cid) + l2cap_data
    acl_hdr = struct.pack('<HH', handle | (0x2 << 12), len(l2cap))
    return acl_hdr + l2cap


def smp_packet(handle: int, opcode: int, payload: bytes) -> bytes:
    smp_data = bytes([opcode]) + payload
    return hci_acl(handle, 0x0006, smp_data)


def le_enable_encryption(handle: int, random: bytes, ediv: int, ltk: bytes) -> bytes:
    params = struct.pack('<H', handle) + random + struct.pack('<H', ediv) + ltk
    return hci_cmd(0x2019, params)


def le_connection_complete(handle: int, addr: bytes, addr_type: int = 0x01) -> bytes:
    subevent = 0x01
    params = bytes([subevent, 0x00]) + struct.pack('<H', handle) + bytes([0x00, addr_type]) + addr + struct.pack('<HHH', 0x0028, 0x0000, 0x0004)
    return hci_evt(0x3E, params)


def cmd_complete(opcode: int, status: int = 0x00) -> bytes:
    params = bytes([0x01]) + struct.pack('<H', opcode) + bytes([status])
    return hci_evt(0x0E, params)


def encryption_change_evt(handle: int, enabled: int = 0x01) -> bytes:
    params = bytes([0x00]) + struct.pack('<H', handle) + bytes([enabled])
    return hci_evt(0x08, params)


def smp_pairing_request(handle: int, io_cap: int = 0x03, auth_req: int = 0x0D, max_key_size: int = 16) -> bytes:
    payload = bytes([io_cap, 0x00, auth_req, max_key_size, 0x0F, 0x0F])
    return smp_packet(handle, 0x01, payload)


def smp_pairing_response(handle: int, io_cap: int = 0x03, auth_req: int = 0x09, max_key_size: int = 16) -> bytes:
    payload = bytes([io_cap, 0x00, auth_req, max_key_size, 0x09, 0x09])
    return smp_packet(handle, 0x02, payload)


def make_dump(filename: str, records: list):
    out = btsnoop_header()
    for i, (data, flags) in enumerate(records):
        out += btsnoop_record(data, flags, ts_offset_us=i * 50000)
    with open(filename, 'wb') as f:
        f.write(out)


OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def dump_01_ble_full_16byte_key():
    addr = bytes([0x69, 0x20, 0xE4, 0xDB, 0x07, 0x67])
    handle = 0x0008
    ltk = bytes.fromhex('695992f68a0ce8d5d321ca883bbf864e')
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x0D, max_key_size=16), 0x04),
        (smp_pairing_response(handle, io_cap=0x03, auth_req=0x09, max_key_size=16), 0x05),
        (le_enable_encryption(handle, b'\x00' * 8, 0x0000, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_01_ble_strong_key.btsnoop'), records)


def dump_02_ble_weak_7byte_key():
    addr = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    handle = 0x0010
    ltk = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]) + bytes(9)
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x05, max_key_size=7), 0x04),
        (smp_pairing_response(handle, io_cap=0x03, auth_req=0x01, max_key_size=7), 0x05),
        (le_enable_encryption(handle, b'\x01' * 8, 0x0001, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_02_ble_weak_7byte_key.btsnoop'), records)


def dump_03_ble_no_encryption():
    addr = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    handle = 0x0005
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x01, max_key_size=7), 0x04),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_03_ble_no_encryption.btsnoop'), records)


def dump_04_ble_static_mac():
    addr = bytes([0xC0, 0xDE, 0xC0, 0xDE, 0xC0, 0xDE])
    handle = 0x0009
    ltk = bytes(range(16))
    records = [
        (le_connection_complete(handle, addr, 0x00), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x0D, max_key_size=16), 0x04),
        (smp_pairing_response(handle, io_cap=0x03, auth_req=0x09, max_key_size=16), 0x05),
        (le_enable_encryption(handle, b'\x00' * 8, 0x0000, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_04_ble_static_mac.btsnoop'), records)


def dump_05_ble_random_mac():
    addr = bytes([0xFA, 0xBB, 0x12, 0x34, 0xAB, 0xCD])
    handle = 0x000A
    ltk = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 4)
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x0D, max_key_size=16), 0x04),
        (smp_pairing_response(handle, io_cap=0x03, auth_req=0x09, max_key_size=16), 0x05),
        (le_enable_encryption(handle, b'\xAB' * 8, 0x0002, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_05_ble_random_mac.btsnoop'), records)


def dump_06_ble_mitm_protection():
    addr = bytes([0x50, 0x51, 0x52, 0x53, 0x54, 0x55])
    handle = 0x000B
    ltk = bytes([0xCA, 0xFE, 0xBA, 0xBE] * 4)
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x01, auth_req=0x0F, max_key_size=16), 0x04),
        (smp_pairing_response(handle, io_cap=0x01, auth_req=0x0D, max_key_size=16), 0x05),
        (le_enable_encryption(handle, b'\xCC' * 8, 0x0005, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_06_ble_mitm_protection.btsnoop'), records)


def dump_07_ble_weak_1byte_key():
    addr = bytes([0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01])
    handle = 0x000C
    ltk = bytes([0xFF]) + bytes(15)
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x01, max_key_size=1), 0x04),
        (smp_pairing_response(handle, io_cap=0x03, auth_req=0x01, max_key_size=1), 0x05),
        (le_enable_encryption(handle, b'\x00' * 8, 0x0000, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_07_ble_extremely_weak_key.btsnoop'), records)


def dump_08_ble_secure_connections():
    addr = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
    handle = 0x000D
    ltk = bytes.fromhex('a1b2c3d4e5f60718293a4b5c6d7e8f90')
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x01, auth_req=0x2D, max_key_size=16), 0x04),
        (smp_pairing_response(handle, io_cap=0x01, auth_req=0x29, max_key_size=16), 0x05),
        (le_enable_encryption(handle, b'\x11' * 8, 0x0010, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_08_ble_secure_connections.btsnoop'), records)


def dump_09_ble_key_size_boundary():
    addr = bytes([0xAA, 0x11, 0x22, 0x33, 0x44, 0x55])
    handle = 0x000E
    ltk = bytes(range(16))
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x05, max_key_size=9), 0x04),
        (smp_pairing_response(handle, io_cap=0x03, auth_req=0x01, max_key_size=9), 0x05),
        (le_enable_encryption(handle, b'\x05' * 8, 0x0006, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_09_ble_borderline_key.btsnoop'), records)


def dump_10_ble_encryption_disabled():
    addr = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])
    handle = 0x000F
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x00, max_key_size=7), 0x04),
        (encryption_change_evt(handle, 0x00), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_10_ble_encryption_disabled.btsnoop'), records)


def dump_11_provided_sample():
    import shutil
    src = '/mnt/user-data/uploads/bleguard_h01_l5q_.pcap'
    dst = os.path.join(OUT_DIR, 'test_11_real_capture_ltk128bit.btsnoop')
    if os.path.exists(src):
        shutil.copy2(src, dst)
    else:
        dump_01_ble_full_16byte_key()


def dump_12_ble_just_works():
    addr = bytes([0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC])
    handle = 0x0011
    ltk = bytes([0x55] * 16)
    records = [
        (le_connection_complete(handle, addr, 0x01), 0x03),
        (cmd_complete(0x2006), 0x03),
        (smp_pairing_request(handle, io_cap=0x03, auth_req=0x00, max_key_size=16), 0x04),
        (smp_pairing_response(handle, io_cap=0x03, auth_req=0x00, max_key_size=16), 0x05),
        (le_enable_encryption(handle, b'\x00' * 8, 0x0000, ltk), 0x02),
        (cmd_complete(0x2019), 0x03),
        (encryption_change_evt(handle, 0x01), 0x03),
    ]
    make_dump(os.path.join(OUT_DIR, 'test_12_ble_just_works_no_mitm.btsnoop'), records)


if __name__ == '__main__':
    dump_01_ble_full_16byte_key()
    dump_02_ble_weak_7byte_key()
    dump_03_ble_no_encryption()
    dump_04_ble_static_mac()
    dump_05_ble_random_mac()
    dump_06_ble_mitm_protection()
    dump_07_ble_weak_1byte_key()
    dump_08_ble_secure_connections()
    dump_09_ble_key_size_boundary()
    dump_10_ble_encryption_disabled()
    dump_11_provided_sample()
    dump_12_ble_just_works()
    print('Сгенерировано 12 тестов в > ', OUT_DIR)
    import glob
    for f in sorted(glob.glob(os.path.join(OUT_DIR, 'test_*.btsnoop'))):
        print(' ', os.path.basename(f), os.path.getsize(f), 'bytes')
