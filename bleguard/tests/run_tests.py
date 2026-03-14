import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bleguard.core import parse_capture, analyze, RISK_OK, RISK_WARN, RISK_CRITICAL, RISK_INFO

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def color_ok(s): return f'\033[92m{s}\033[0m'
def color_fail(s): return f'\033[91m{s}\033[0m'
def color_warn(s): return f'\033[93m{s}\033[0m'
def color_dim(s): return f'\033[90m{s}\033[0m'
def color_bold(s): return f'\033[1m{s}\033[0m'


EXPECTED = {
    'test_01_ble_strong_key.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 16,
        'overall_risk_max': RISK_WARN,
        'description': 'BLE, 128-bit key — сильный ключ',
    },
    'test_02_ble_weak_7byte_key.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 7,
        'overall_risk': RISK_CRITICAL,
        'description': 'BLE, 56-bit key — критически слабый (KNOB-уязвимость)',
    },
    'test_03_ble_no_encryption.btsnoop': {
        'is_ble': True,
        'encryption_enabled': False,
        'overall_risk': RISK_CRITICAL,
        'description': 'BLE, нет шифрования',
    },
    'test_04_ble_static_mac.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 16,
        'static_mac': True,
        'description': 'BLE, статичный MAC + сильный ключ',
    },
    'test_05_ble_random_mac.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 16,
        'random_mac': True,
        'description': 'BLE, случайный MAC + сильный ключ',
    },
    'test_06_ble_mitm_protection.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 16,
        'has_mitm': True,
        'description': 'BLE, MITM-защита включена',
    },
    'test_07_ble_extremely_weak_key.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 1,
        'overall_risk': RISK_CRITICAL,
        'description': 'BLE, 8-bit key — крайне слабый',
    },
    'test_08_ble_secure_connections.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 16,
        'has_secure_connections': True,
        'description': 'BLE, LE Secure Connections включены',
    },
    'test_09_ble_borderline_key.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 9,
        'overall_risk': RISK_WARN,
        'description': 'BLE, 72-bit key — пограничный (предупреждение)',
    },
    'test_10_ble_encryption_disabled.btsnoop': {
        'is_ble': True,
        'description': 'BLE, шифрование явно выключено',
    },
    'test_11_real_capture_ltk128bit.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 16,
        'ltk_contains': '695992f68a0ce8d5',
        'description': 'Реальный захват: LTK 128 бит (из Wireshark)',
    },
    'test_12_ble_just_works_no_mitm.btsnoop': {
        'is_ble': True,
        'encryption_enabled': True,
        'key_size_bytes': 16,
        'description': 'BLE, Just Works (без MITM-защиты)',
    },
}


def run_tests():
    print(color_bold('\n═══════════════════════════════════════════════════'))
    print(color_bold(' BLEGuard — Test Suite'))
    print(color_bold('═══════════════════════════════════════════════════\n'))

    passed = 0
    failed = 0
    warnings = 0

    for filename, expected in EXPECTED.items():
        path = os.path.join(TESTS_DIR, filename)
        desc = expected.get('description', filename)

        print(color_bold(f'  {filename}'))
        print(color_dim(f'  {desc}'))

        if not os.path.exists(path):
            print(color_fail(f'  SKIP: file not found\n'))
            warnings += 1
            continue

        try:
            parse_result = parse_capture(path)
            report = analyze(parse_result)
        except Exception as e:
            print(color_fail(f'  FAIL: exception during analysis: {e}\n'))
            failed += 1
            continue

        test_passed = True
        checks = []

        if 'is_ble' in expected:
            ok = parse_result.is_ble == expected['is_ble']
            checks.append(('is_ble', expected['is_ble'], parse_result.is_ble, ok))
            if not ok:
                test_passed = False

        if 'encryption_enabled' in expected:
            ok = parse_result.encryption.enabled == expected['encryption_enabled']
            checks.append(('encryption.enabled', expected['encryption_enabled'], parse_result.encryption.enabled, ok))
            if not ok:
                test_passed = False

        if 'key_size_bytes' in expected:
            actual_ks = parse_result.encryption.key_size_bytes
            ok = actual_ks == expected['key_size_bytes']
            checks.append(('key_size_bytes', expected['key_size_bytes'], actual_ks, ok))
            if not ok:
                test_passed = False

        if 'overall_risk' in expected:
            ok = report.overall_risk == expected['overall_risk']
            checks.append(('overall_risk', expected['overall_risk'], report.overall_risk, ok))
            if not ok:
                test_passed = False

        if 'overall_risk_max' in expected:
            risk_order = [RISK_OK, RISK_INFO, RISK_WARN, RISK_CRITICAL]
            ok = risk_order.index(report.overall_risk) <= risk_order.index(expected['overall_risk_max'])
            checks.append(('overall_risk_max', f'<={expected["overall_risk_max"]}', report.overall_risk, ok))
            if not ok:
                test_passed = False

        if 'ltk_contains' in expected:
            ltk_hex = parse_result.encryption.ltk_hex.lower()
            ok = expected['ltk_contains'].lower() in ltk_hex
            checks.append(('ltk_contains', expected['ltk_contains'], ltk_hex[:32] or 'none', ok))
            if not ok:
                test_passed = False

        if 'static_mac' in expected:
            has_static = parse_result.connection and not parse_result.connection.is_random_address
            ok = has_static == expected['static_mac']
            checks.append(('static_mac', expected['static_mac'], has_static, ok))
            if not ok:
                test_passed = False

        if 'random_mac' in expected:
            has_random = parse_result.connection and parse_result.connection.is_random_address
            ok = has_random == expected['random_mac']
            checks.append(('random_mac', expected['random_mac'], has_random, ok))
            if not ok:
                test_passed = False

        if 'has_mitm' in expected:
            smp = parse_result.pairing_request or parse_result.pairing_response
            has_mitm = smp is not None and smp.mitm_protection
            ok = has_mitm == expected['has_mitm']
            checks.append(('has_mitm', expected['has_mitm'], has_mitm, ok))
            if not ok:
                test_passed = False

        if 'has_secure_connections' in expected:
            smp = parse_result.pairing_request or parse_result.pairing_response
            has_sc = smp is not None and smp.secure_connections
            ok = has_sc == expected['has_secure_connections']
            checks.append(('has_sc', expected['has_secure_connections'], has_sc, ok))
            if not ok:
                test_passed = False

        for name, exp_val, got_val, ok in checks:
            symbol = color_ok('  ✓') if ok else color_fail('  ✗')
            status = color_ok('OK') if ok else color_fail(f'FAIL (expected={exp_val}, got={got_val})')
            print(f'{symbol} {name}: {status}')

        print(color_dim(f'  Risk: {report.overall_risk} | Packets: {parse_result.raw_records_count} | Connection: {parse_result.connection_type}'))

        if test_passed:
            print(color_ok('  → PASSED\n'))
            passed += 1
        else:
            print(color_fail('  → FAILED\n'))
            failed += 1

    total = passed + failed + warnings
    print(color_bold('═══════════════════════════════════════════════════'))
    print(color_bold(f' Results: {total} tests | ') + color_ok(f'{passed} passed') + ' | ' + (color_fail(f'{failed} failed') if failed else color_dim('0 failed')) + ' | ' + color_warn(f'{warnings} skipped'))
    print(color_bold('═══════════════════════════════════════════════════\n'))

    return failed == 0


if __name__ == '__main__':
    ok = run_tests()
    sys.exit(0 if ok else 1)
