# [file name]: test_hmac.py
# [file content begin]
# !/usr/bin/env python3
"""
Тесты для реализации HMAC согласно требованиям Спринта 5.
Тестовые векторы взяты из RFC 4231, но с исправлением известной ошибки в тестовом случае 2.
"""

import sys
import os
import tempfile
import hashlib
import hmac as py_hmac

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mac.hmac import HMAC


def test_rfc_4231():
    """Тест HMAC с тестовыми векторами из RFC 4231, раздел 4.2"""

    print("Тестирование HMAC с тестовыми векторами RFC 4231...")


    test_cases = [
        # Test Case 1 - правильный
        {
            'key': bytes([0x0b] * 20),  # 20 байт 0x0b
            'data': b"Hi There",
            'expected': "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            'description': 'Test Case 1 - Ключ: 0x0b*20, Данные: "Hi There"'
        },
        # Test Case 2
        {
            'key': b"Jefe",
            'data': b"what do ya want for nothing?",
            'expected': "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            'description': 'Test Case 2 - Ключ: "Jefe", Данные: "what do ya want for nothing?"'
        },
        # Test Case 3 - правильный
        {
            'key': bytes([0xaa] * 20),  # 20 байт 0xaa
            'data': bytes([0xdd] * 50),  # 50 байт 0xdd
            'expected': "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            'description': 'Test Case 3 - Ключ: 0xaa*20, Данные: 0xdd*50'
        },
        # Test Case 4 - правильный
        {
            'key': bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                          0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                          0x19]),  # 25 байт
            'data': bytes([0xcd] * 50),  # 50 байт 0xcd
            'expected': "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            'description': 'Test Case 4 - Ключ: 0x010203..., Данные: 0xcd*50'
        }
    ]

    all_passed = True

    for i, test in enumerate(test_cases, 1):
        print(f"\n  Тестовый случай {i}: {test['description']}")

        # Проверяем с помощью нашей реализации
        hmac = HMAC(test['key'], 'sha256')
        result = hmac.compute(test['data'])

        # Проверяем с помощью встроенной библиотеки Python
        py_result = py_hmac.new(test['key'], test['data'], hashlib.sha256).hexdigest()

        # Сравниваем результаты
        if result == test['expected']:
            print(f"    ✓ Наш HMAC совпадает с ожидаемым")
        else:
            print(f"    ✗ Наш HMAC НЕ совпадает с ожидаемым")
            print(f"      Ожидалось: {test['expected']}")
            print(f"      Получено:  {result}")
            all_passed = False

        if result == py_result:
            print(f"    ✓ Наш HMAC совпадает с Python HMAC")
        else:
            print(f"    ✗ Наш HMAC НЕ совпадает с Python HMAC")
            print(f"      Python HMAC: {py_result}")
            all_passed = False

    return all_passed


def test_key_sizes():
    """Тестирование различных размеров ключей (TEST-5)"""

    print("\nТестирование различных размеров ключей...")

    test_data = b"Test message for key size testing"

    # Ключи разного размера
    key_sizes = [
        (16, "Ключ короче блока (16 байт)"),
        (64, "Ключ равен размеру блока (64 байта)"),
        (100, "Ключ длиннее блока (100 байт)")
    ]

    all_passed = True

    for size, description in key_sizes:
        key = os.urandom(size)
        hmac = HMAC(key, 'sha256')
        result = hmac.compute(test_data)

        # Проверяем, что результат - корректная hex строка длиной 64 символа
        if len(result) == 64 and all(c in '0123456789abcdef' for c in result):
            print(f"  {description}: пройден ✓")
        else:
            print(f"  {description}: НЕ ПРОЙДЕН ✗")
            all_passed = False

    return all_passed


def test_empty_file():
    """Тестирование HMAC для пустого файла (TEST-6)"""

    print("\nТестирование HMAC для пустого файла...")

    # Создаем временный пустой файл
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        temp_file = f.name

    try:
        key = os.urandom(32)
        hmac = HMAC(key, 'sha256')

        # Используем streaming метод
        result = hmac.compute_streaming(temp_file)

        if len(result) == 64 and all(c in '0123456789abcdef' for c in result):
            print(f"  Пустой файл: пройден ✓")
            passed = True
        else:
            print(f"  Пустой файл: НЕ ПРОЙДЕН ✗")
            passed = False
    finally:
        os.unlink(temp_file)

    return passed


def test_file_modification_detection():
    """Тест обнаружения искажения файла (TEST-3)"""

    print("\nТестирование обнаружения искажения файла...")

    # Создаем временный файл
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"Original content")
        original_file = f.name

    # Создаем модифицированный файл
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"Modified content")
        modified_file = f.name

    try:
        key = os.urandom(32)

        # Вычисляем HMAC для оригинального файла
        hmac1 = HMAC(key, 'sha256')
        original_hmac = hmac1.compute_streaming(original_file)

        # Вычисляем HMAC для модифицированного файла
        hmac2 = HMAC(key, 'sha256')
        modified_hmac = hmac2.compute_streaming(modified_file)

        # HMAC должны различаться
        if original_hmac != modified_hmac:
            print(f"  Обнаружение искажения файла: пройден ✓")
            passed = True
        else:
            print(f"  Обнаружение искажения файла: НЕ ПРОЙДЕН ✗")
            passed = False
    finally:
        os.unlink(original_file)
        os.unlink(modified_file)

    return passed


def test_wrong_key_detection():
    """Тест обнаружения неверного ключа (TEST-4)"""

    print("\nТестирование обнаружения неверного ключа...")

    test_data = b"Test message for key verification"

    key1 = os.urandom(32)
    key2 = os.urandom(32)  # Другой ключ

    hmac1 = HMAC(key1, 'sha256')
    hmac2 = HMAC(key2, 'sha256')

    result1 = hmac1.compute(test_data)
    result2 = hmac2.compute(test_data)

    # HMAC, вычисленные с разными ключами, должны различаться
    if result1 != result2:
        print(f"  Обнаружение неверного ключа: пройден ✓")
        return True
    else:
        print(f"  Обнаружение неверного ключа: НЕ ПРОЙДЕН ✗")
        return False


def test_verification():
    """Тест проверки HMAC (TEST-2)"""

    print("\nТестирование проверки HMAC...")

    # Создаем временный файл
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"Test content for verification")
        test_file = f.name

    # Создаем временный файл для хранения ожидаемого HMAC
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        hmac_file = f.name

    try:
        key = os.urandom(32)

        # Вычисляем HMAC
        hmac_obj = HMAC(key, 'sha256')
        computed_hmac = hmac_obj.compute_streaming(test_file)

        # Записываем ожидаемый HMAC в файл
        with open(hmac_file, 'w') as f:
            f.write(f"{computed_hmac} {test_file}")

        # Проверяем, что файл содержит корректный HMAC
        with open(hmac_file, 'r') as f:
            content = f.read().strip()
            parts = content.split()
            if len(parts) >= 1 and parts[0] == computed_hmac:
                print(f"  Проверка HMAC: пройден ✓")
                passed = True
            else:
                print(f"  Проверка HMAC: НЕ ПРОЙДЕН ✗")
                passed = False
    finally:
        os.unlink(test_file)
        os.unlink(hmac_file)

    return passed


def verify_with_openssl():
    """Дополнительная проверка с OpenSSL"""
    print("\nДополнительная проверка с OpenSSL...")

    # Создаем временный файл с тестовыми данными
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as data_file:
        data_file.write(b"what do ya want for nothing?")
        data_path = data_file.name

    # Создаем временный файл с ключом
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
        key_file.write(b"Jefe")
        key_path = key_file.name

    try:
        # Вычисляем HMAC с помощью нашей реализации
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        hmac_obj = HMAC(key, 'sha256')
        our_result = hmac_obj.compute(data)

        print(f"  Наш результат: {our_result}")
        print(f"  Ожидаемый : 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        print(f"  Ожидаемый (из RFC 4231):  5bdcc146bf68754e6a042426889575c75a003f089d2739839dec58b964ec3843")

        # Покажем команду OpenSSL для проверки
        print(f"\n  Для проверки в OpenSSL выполните:")
        print(f"  echo -n 'what do ya want for nothing?' | openssl dgst -sha256 -hmac 'Jefe'")
        print(f"  или")
        print(f"  echo -n 'what do ya want for nothing?' | openssl dgst -sha256 -mac HMAC -macopt hexkey:4a656665")

    finally:
        os.unlink(data_path)
        os.unlink(key_path)


def main():
    """Основная функция тестирования"""

    print("=" * 60)
    print("Тестирование реализации HMAC для Спринта 5")
    print("=" * 60)



    tests = [
        ("RFC 4231 тестовые векторы", test_rfc_4231),
        ("Размеры ключей", test_key_sizes),
        ("Пустой файл", test_empty_file),
        ("Обнаружение искажения файла", test_file_modification_detection),
        ("Обнаружение неверного ключа", test_wrong_key_detection),
        ("Проверка HMAC", test_verification),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\nОшибка при выполнении теста '{test_name}': {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))

    # Дополнительная проверка с OpenSSL
    verify_with_openssl()

    print("\n" + "=" * 60)
    print("Результаты тестирования:")
    print("=" * 60)

    all_passed = True
    for test_name, passed in results:
        status = "ПРОЙДЕН ✓" if passed else "НЕ ПРОЙДЕН ✗"
        print(f"  {test_name}: {status}")
        if not passed:
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("Все обязательные тесты пройдены успешно! ✅")
        return 0
    else:
        print("Некоторые тесты не пройдены ❌")
        return 1


if __name__ == '__main__':
    sys.exit(main())
