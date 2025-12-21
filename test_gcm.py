# [file name]: test_gcm.py
# [file content begin]
import os
import sys

sys.path.append('.')

from modes.gcm import GCM, AuthenticationError


def test_gcm_basic():
    """Базовый тест шифрования и дешифрования GCM"""
    print("Тест 1: Базовое шифрование и дешифрование")

    try:
        key = os.urandom(16)
        plaintext = b"Hello GCM world!"
        aad = b"associated data"

        # Шифрование
        gcm = GCM(key)
        ciphertext = gcm.encrypt(plaintext, aad)

        # Дешифрование
        gcm2 = GCM(key, gcm.nonce)
        decrypted = gcm2.decrypt(ciphertext, aad)

        assert decrypted == plaintext, "Дешифрование не совпадает с исходным текстом"
        print("  ✓ Базовый тест пройден")
        return True
    except Exception as e:
        print(f"  ✗ Базовый тест не пройден: {e}")
        return False


def test_gcm_aad_tamper():
    """Тест проверки аутентификации при неверном AAD"""
    print("Тест 2: Проверка аутентификации при неверном AAD")

    try:
        key = os.urandom(16)
        plaintext = b"Secret message"
        aad_correct = b"correct_aad"
        aad_wrong = b"wrong_aad"

        # Шифрование с корректным AAD
        gcm = GCM(key)
        ciphertext = gcm.encrypt(plaintext, aad_correct)

        # Попытка дешифрования с неверным AAD
        gcm2 = GCM(key, gcm.nonce)

        try:
            result = gcm2.decrypt(ciphertext, aad_wrong)
            print("  ✗ Ошибка: дешифрование должно было завершиться ошибкой")
            return False
        except AuthenticationError:
            print("  ✓ Корректно завершилось с ошибкой при неверном AAD")
            return True
    except Exception as e:
        print(f"  ✗ Тест завершился с исключением: {e}")
        return False


def test_gcm_ciphertext_tamper():
    """Тест проверки аутентификации при искаженном шифротексте"""
    print("Тест 3: Проверка аутентификации при искаженном шифротексте")

    try:
        key = os.urandom(16)
        plaintext = b"Another secret message"
        aad = b"associated_data"

        # Шифрование
        gcm = GCM(key)
        ciphertext = gcm.encrypt(plaintext, aad)

        # Искажение шифротекста (переворачиваем один бит)
        tampered = bytearray(ciphertext)
        tampered[28] ^= 0x01  # Меняем бит в шифротексте

        # Попытка дешифрования искаженного шифротекста
        gcm2 = GCM(key, gcm.nonce)

        try:
            result = gcm2.decrypt(bytes(tampered), aad)
            print("  ✗ Ошибка: дешифрование должно было завершиться ошибкой")
            return False
        except AuthenticationError:
            print("  ✓ Корректно завершилось с ошибкой при искаженном шифротексте")
            return True
    except Exception as e:
        print(f"  ✗ Тест завершился с исключением: {e}")
        return False


def test_gcm_empty_aad():
    """Тест с пустым AAD"""
    print("Тест 4: Работа с пустым AAD")

    try:
        key = os.urandom(16)
        plaintext = b"Message without AAD"
        aad = b""

        # Шифрование
        gcm = GCM(key)
        ciphertext = gcm.encrypt(plaintext, aad)

        # Дешифрование
        gcm2 = GCM(key, gcm.nonce)
        decrypted = gcm2.decrypt(ciphertext, aad)

        assert decrypted == plaintext, "Дешифрование не совпадает с исходным текстом"
        print("  ✓ Тест с пустым AAD пройден")
        return True
    except Exception as e:
        print(f"  ✗ Тест с пустым AAD не пройден: {e}")
        return False


def test_gcm_nist_vector():
    """Тест с тестовым вектором от NIST"""
    print("Тест 5: Тестовый вектор NIST")

    try:
        # Тестовый вектор из NIST SP 800-38D, Appendix B
        key = bytes.fromhex("00000000000000000000000000000000")
        nonce = bytes.fromhex("000000000000000000000000")
        aad = b""
        plaintext = b""

        # Ожидаемый результат
        expected_ciphertext = b""
        expected_tag = bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")

        # Шифрование
        gcm = GCM(key, nonce)
        result = gcm.encrypt(plaintext, aad)

        # Проверяем формат: nonce (12) + ciphertext (0) + tag (16)
        assert len(result) == 28
        assert result[:12] == nonce
        assert result[12:-16] == expected_ciphertext
        assert result[-16:] == expected_tag

        # Дешифрование
        decrypted = gcm.decrypt(result, aad)
        assert decrypted == plaintext

        print("  ✓ Тестовый вектор NIST пройден")
        return True
    except Exception as e:
        print(f"  ✗ Тестовый вектор NIST не пройден: {e}")
        return False


def test_gcm_nonce_uniqueness():
    """Тест уникальности nonce"""
    print("Тест 6: Уникальность nonce")

    try:
        key = os.urandom(16)
        plaintext = b"Test message"

        # Генерация 100 уникальных nonce
        nonces = set()
        for _ in range(100):
            gcm = GCM(key)
            nonces.add(gcm.nonce)

        assert len(nonces) == 100, "Некоторые nonce совпадают"
        print("  ✓ Все 100 nonce уникальны")
        return True
    except Exception as e:
        print(f"  ✗ Тест уникальности nonce не пройден: {e}")
        return False


def main():
    print("Запуск тестов GCM...")
    print("=" * 50)

    tests = [
        test_gcm_basic,
        test_gcm_aad_tamper,
        test_gcm_ciphertext_tamper,
        test_gcm_empty_aad,
        test_gcm_nist_vector,
        test_gcm_nonce_uniqueness,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"  ✗ Тест завершился с неожиданным исключением: {e}")
        print()

    print("=" * 50)
    print(f"Итог: {passed}/{total} тестов пройдено")

    if passed == total:
        print("Все тесты успешно пройдены!")
        return 0
    else:
        print("Некоторые тесты не пройдены")
        return 1


if __name__ == '__main__':
    sys.exit(main())
# [file content end]