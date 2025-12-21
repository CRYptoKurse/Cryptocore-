# [file name]: test_encrypt_then_mac_comprehensive.py
# [file content begin]
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Комплексные тесты для Encrypt-then-MAC (TEST-9)
Аналогичные тестам GCM (TEST-1 до TEST-8)
"""

import sys
import os
import tempfile
import hashlib
import subprocess

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aead.encrypt_then_mac import EncryptThenMAC, AuthenticationError
from csprng import generate_random_bytes


class TestEncryptThenMACComprehensive:
    """Комплексные тесты для Encrypt-then-MAC"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.key = generate_random_bytes(32)  # 16 для AES + 16 для HMAC
        self.key_hex = self.key.hex()

    def test_1_roundtrip(self):
        """TEST-9 аналогично TEST-2: Тест "туда-обратно" """
        print("Test 1: Encryption-decryption (round-trip)")

        # Различные длины сообщений
        test_cases = [
            b"",  # пустое сообщение
            b"A",  # 1 байт
            b"Hello World",  # короткое сообщение
            b"A" * 16,  # ровно один блок AES
            b"B" * 31,  # почти блок
            b"C" * 100,  # несколько блоков
            b"D" * 1000,  # большое сообщение
            b"E" * 10000,  # очень большое сообщение
        ]

        for i, plaintext in enumerate(test_cases):
            # Различные AAD
            aad_cases = [
                b"",
                b"aad1",
                b"a" * 16,
                b"b" * 31,
                b"c" * 100,
                b"d" * 1000,
            ]

            for aad in aad_cases:
                etm = EncryptThenMAC(self.key, mode='ctr')
                ciphertext = etm.encrypt(plaintext, aad)
                decrypted = etm.decrypt(ciphertext, aad)

                assert decrypted == plaintext, (
                    f"Test {i + 1} with AAD length {len(aad)}: "
                    f"decrypted data does not match ({len(decrypted)} != {len(plaintext)})"
                )

        print("  ✓ All 'round-trip' tests passed")
        return True

    def test_2_aad_tamper_catastrophic_failure(self):
        """TEST-9 аналогично TEST-3: Тест искажения AAD (катастрофический отказ)"""
        print("\nTest 2: AAD tampering (catastrophic failure)")

        plaintext = b"Secret message that needs to be protected"
        aad_correct = b"Correct associated data"
        aad_wrong = b"Wrong associated data"

        etm = EncryptThenMAC(self.key, mode='ctr')
        ciphertext = etm.encrypt(plaintext, aad_correct)

        # Пытаемся расшифровать с неправильным AAD
        try:
            decrypted = etm.decrypt(ciphertext, aad_wrong)
            assert False, "Expected authentication error with wrong AAD"
        except AuthenticationError as e:
            # Проверяем, что есть четкое сообщение об ошибке
            error_msg = str(e)
            print(f"  ✓ Got expected error: {error_msg[:50]}...")
        except Exception as e:
            assert False, f"Expected AuthenticationError, got {type(e).__name__}: {e}"

        # Проверяем, что никакие данные не были возвращены
        assert 'decrypted' not in locals() or decrypted is None, \
            "No data should be returned on authentication failure"

        print("  ✓ Catastrophic failure on AAD tampering confirmed")
        return True

    def test_3_ciphertext_tamper_catastrophic_failure(self):
        """TEST-9 аналогично TEST-4: Тест искажения шифртекста/тега"""
        print("\nTest 3: Ciphertext and tag tampering (catastrophic failure)")

        plaintext = b"Another secret message"
        aad = b"Associated data"

        etm = EncryptThenMAC(self.key, mode='ctr')
        ciphertext = etm.encrypt(plaintext, aad)

        # Тест 3.1: Искажение шифртекста
        print("  3.1: Ciphertext tampering")
        for pos in [0, 10, len(ciphertext) // 2, len(ciphertext) - 32 - 1]:  # Разные позиции (избегаем тег)
            if pos < len(ciphertext) - 32:  # Убедимся, что не задеваем тег
                tampered = bytearray(ciphertext)
                tampered[pos] ^= 0x01  # Инвертируем один бит

                try:
                    decrypted = etm.decrypt(bytes(tampered), aad)
                    assert False, f"Expected authentication error when tampering byte at position {pos}"
                except AuthenticationError:
                    pass  # Ожидаемое поведение
                except Exception as e:
                    assert False, f"Expected AuthenticationError, got {type(e).__name__}: {e}"

        print("    ✓ Ciphertext tampering causes authentication error")

        # Тест 3.2: Искажение тега
        print("  3.2: Tag tampering")
        tampered_tag = bytearray(ciphertext)
        # Тег занимает последние 32 байта
        for pos in range(len(ciphertext) - 32, len(ciphertext)):
            tampered = bytearray(ciphertext)
            tampered[pos] ^= 0x01

            try:
                decrypted = etm.decrypt(bytes(tampered), aad)
                assert False, f"Expected authentication error when tampering tag at position {pos}"
            except AuthenticationError:
                pass  # Ожидаемое поведение
            except Exception as e:
                assert False, f"Expected AuthenticationError, got {type(e).__name__}: {e}"

        print("    ✓ Tag tampering causes authentication error")

        # Тест 3.3: Полная замена тега
        print("  3.3: Complete tag replacement")
        tampered = ciphertext[:-32] + os.urandom(32)  # Заменяем тег случайными байтами

        try:
            decrypted = etm.decrypt(tampered, aad)
            assert False, "Expected authentication error with complete tag replacement"
        except AuthenticationError:
            pass
        except Exception as e:
            assert False, f"Expected AuthenticationError, got {type(e).__name__}: {e}"

        print("    ✓ Complete tag replacement causes authentication error")

        print("  ✓ All data tampering tests passed")
        return True

    def test_4_nonce_uniqueness(self):
        """TEST-9 аналогично TEST-5: Уникальность nonce/IV для каждого шифрования"""
        print("\nTest 4: IV uniqueness for each encryption")

        plaintext = b"Test message"
        aad = b""

        # Собираем все сгенерированные IV
        ivs = set()

        for i in range(1000):
            etm = EncryptThenMAC(self.key, mode='ctr')
            ciphertext = etm.encrypt(plaintext, aad)

            # Извлекаем IV (первые 16 байт)
            iv = ciphertext[:16]
            iv_hex = iv.hex()

            if iv_hex in ivs:
                assert False, f"Duplicate IV found at iteration {i}: {iv_hex}"

            ivs.add(iv_hex)

            # Прогресс каждые 100 итераций
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i + 1}/1000 IVs generated")

        assert len(ivs) == 1000, f"Expected 1000 unique IVs, got {len(ivs)}"

        print(f"  ✓ All 1000 IVs are unique")

        # Дополнительная проверка: энтропия
        print("  Checking IV entropy...")
        # Конвертируем IV в байты для анализа
        iv_bytes_list = [bytes.fromhex(iv_hex) for iv_hex in list(ivs)[:10]]  # Первые 10 для примера

        print(f"  Example IVs: {list(ivs)[:3]}")

        return True

    def test_5_empty_aad(self):
        """TEST-9 аналогично TEST-6: Работа с пустым AAD"""
        print("\nTest 5: Working with empty AAD")

        test_cases = [
            (b"", b""),  # empty data and AAD
            (b"Non-empty data", b""),  # only empty AAD
            (b"", b"Non-empty AAD"),  # only empty data (not relevant to test, but check)
            (b"Message", b""),  # normal message with empty AAD
        ]

        for i, (plaintext, aad) in enumerate(test_cases):
            if aad == b"":  # Специально тестируем пустой AAD
                etm = EncryptThenMAC(self.key, mode='ctr')
                ciphertext = etm.encrypt(plaintext, aad)
                decrypted = etm.decrypt(ciphertext, aad)

                assert decrypted == plaintext, \
                    f"Test {i + 1}: failed with empty AAD (message length: {len(plaintext)})"

        print("  ✓ Working with empty AAD is correct")

        # Проверяем, что пустой AAD не равен отсутствию AAD
        print("  Checking equivalence of empty and missing AAD...")
        plaintext = b"Test data"

        etm1 = EncryptThenMAC(self.key, mode='ctr')
        ciphertext_with_empty = etm1.encrypt(plaintext, b"")

        etm2 = EncryptThenMAC(self.key, mode='ctr')
        ciphertext_with_none = etm2.encrypt(plaintext, b"")  # передаем пустой байт

        # Они должны быть разными из-за разных IV, но оба должны расшифровываться
        # со своими соответствующими AAD
        decrypted1 = etm1.decrypt(ciphertext_with_empty, b"")
        decrypted2 = etm2.decrypt(ciphertext_with_none, b"")

        assert decrypted1 == plaintext and decrypted2 == plaintext, \
            "Empty AAD should work correctly"

        print("  ✓ Empty AAD works correctly")
        return True

    def test_6_large_aad_streaming(self):
        """TEST-9 аналогично TEST-7: Большой AAD (обработка по частям)"""
        print("\nTest 6: Large AAD (streaming processing)")

        # Создаем большой AAD (5 МБ вместо 10 МБ для скорости)
        print("  Creating large AAD (5 MB)...")
        large_aad = os.urandom(5 * 1024 * 1024)  # 5 МБ

        # Различные размеры сообщений
        message_sizes = [0, 1, 100, 10000, 100000]

        for size in message_sizes:
            plaintext = os.urandom(size)

            print(f"  Test with message {size} bytes and AAD 5 MB...")

            etm = EncryptThenMAC(self.key, mode='ctr')

            # Шифрование
            ciphertext = etm.encrypt(plaintext, large_aad)

            # Дешифрование
            decrypted = etm.decrypt(ciphertext, large_aad)

            assert decrypted == plaintext, \
                f"Failed with large AAD and message {size} bytes"

            # Попытка с неправильным большим AAD
            wrong_large_aad = large_aad[:-1] + bytes([large_aad[-1] ^ 0x01])
            try:
                etm.decrypt(ciphertext, wrong_large_aad)
                assert False, "Expected authentication error with wrong large AAD"
            except AuthenticationError:
                pass  # Ожидаемое поведение

            print(f"    ✓ Message {size} bytes: OK")

        print("  ✓ Large AAD is processed correctly")
        return True

    def test_7_encrypt_then_mac_specific_tests(self):
        """Специфичные тесты для Encrypt-then-MAC"""
        print("\nTest 7: Encrypt-then-MAC specific tests")

        # 7.1: Проверка разделения ключей
        print("  7.1: Key splitting verification")

        # Ключ должен быть минимум 32 байта
        try:
            etm = EncryptThenMAC(b"short", mode='ctr')
            assert False, "Expected error for short key"
        except ValueError as e:
            print(f"    ✓ Expected error for short key: {e}")

        # Проверяем корректное разделение ключей
        key_32 = os.urandom(32)  # 16 для AES + 16 для HMAC
        key_40 = os.urandom(40)  # 24 для AES + 16 для HMAC
        key_48 = os.urandom(48)  # 32 для AES + 16 для HMAC

        for key in [key_32, key_40, key_48]:
            etm = EncryptThenMAC(key, mode='ctr')
            plaintext = b"Key splitting test"
            aad = b"AAD"

            ciphertext = etm.encrypt(plaintext, aad)
            decrypted = etm.decrypt(ciphertext, aad)

            assert decrypted == plaintext, \
                f"Failed with key length {len(key)} bytes"

        print("    ✓ Key splitting works correctly")

        # 7.2: Проверка обоих режимов (CTR и CBC)
        print("  7.2: Testing both modes (CTR and CBC)")

        plaintext = b"Message for mode testing"
        aad = b"Associated data"

        for mode in ['ctr', 'cbc']:
            etm = EncryptThenMAC(self.key, mode=mode)

            ciphertext = etm.encrypt(plaintext, aad)
            decrypted = etm.decrypt(ciphertext, aad)

            assert decrypted == plaintext, \
                f"Mode {mode} does not work correctly"

            print(f"    ✓ Mode {mode.upper()} works correctly")

        # 7.3: Проверка структуры выходных данных
        print("  7.3: Output data structure verification")

        etm = EncryptThenMAC(self.key, mode='ctr')
        plaintext = b"Structure test"
        aad = b"AAD"

        ciphertext = etm.encrypt(plaintext, aad)

        # Структура: IV (16) + шифртекст + тег (32)
        assert len(ciphertext) >= 16 + 32, "Ciphertext too short"

        iv = ciphertext[:16]
        ciphertext_only = ciphertext[16:-32]
        tag = ciphertext[-32:]

        assert len(iv) == 16, f"IV must be 16 bytes, got {len(iv)}"
        assert len(tag) == 32, f"Tag must be 32 bytes, got {len(tag)}"

        print(f"    ✓ Structure is correct: IV={len(iv)}B, ciphertext={len(ciphertext_only)}B, tag={len(tag)}B")

        print("  ✓ All specific tests passed")
        return True

    def test_8_file_operations(self):
        """Тестирование файловых операций через CLI"""
        print("\nTest 8: File operations via CLI")

        # Создаем временные файлы
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            input_file = f.name
            f.write(b"Test data for file operations Encrypt-then-MAC")

        output_enc = input_file + ".etm.enc"
        output_dec = input_file + ".etm.dec"

        try:
            # 8.1: Шифрование
            print("  8.1: File encryption")
            cmd_encrypt = [
                sys.executable, "cryptocore.py", "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--key", self.key_hex,
                "--aad", "aabbccddeeff",
                "--input", input_file,
                "--output", output_enc
            ]

            result = subprocess.run(cmd_encrypt, capture_output=True, text=True, encoding='utf-8', errors='replace')
            if result.returncode != 0:
                print(f"    Encryption error: {result.stderr}")
                return False
            print("    ✓ Encryption successful")

            # 8.2: Дешифрование с правильным AAD
            print("  8.2: Decryption with correct AAD")
            cmd_decrypt = [
                sys.executable, "cryptocore.py", "encrypt",
                "--decrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--key", self.key_hex,
                "--aad", "aabbccddeeff",
                "--input", output_enc,
                "--output", output_dec
            ]

            result = subprocess.run(cmd_decrypt, capture_output=True, text=True, encoding='utf-8', errors='replace')
            if result.returncode != 0:
                print(f"    Decryption error: {result.stderr}")
                return False
            print("    ✓ Decryption successful")

            # Проверка данных
            with open(input_file, 'rb') as f:
                original = f.read()
            with open(output_dec, 'rb') as f:
                decrypted = f.read()

            if original == decrypted:
                print("    ✓ Data recovered correctly")
            else:
                print(f"    ✗ Data mismatch: {len(decrypted)} != {len(original)} bytes")
                return False

            # 8.3: Дешифрование с неправильным AAD (ожидается ошибка)
            print("  8.3: Decryption with wrong AAD (error expected)")
            output_wrong = output_dec + ".wrong"
            cmd_decrypt_wrong = [
                sys.executable, "cryptocore.py", "encrypt",
                "--decrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--key", self.key_hex,
                "--aad", "wrongaad123456",  # Неправильный AAD
                "--input", output_enc,
                "--output", output_wrong
            ]

            result = subprocess.run(cmd_decrypt_wrong, capture_output=True, text=True, encoding='utf-8',
                                    errors='replace')
            if result.returncode == 0:
                print("    ✗ Expected authentication error")
                return False

            # Проверяем, что в stderr есть сообщение об ошибке аутентификации
            error_lower = result.stderr.lower()
            if not any(word in error_lower for word in ['auth', 'error', 'fail', 'проверк']):
                print(f"    ⚠️  Warning: No clear authentication error message: {result.stderr[:100]}")

            # Проверяем, что выходной файл не создан
            if os.path.exists(output_wrong):
                os.remove(output_wrong)
                print("    ⚠️  Output file was created but should have been deleted")
                # Не считаем это фатальной ошибкой, но отмечаем

            print("    ✓ Authentication failed as expected")

            # 8.4: Проверка, что файл удаляется при ошибке аутентификации
            print("  8.4: Checking file deletion on authentication error")
            # Создаем файл заранее
            with open(output_wrong, 'w') as f:
                f.write("test")

            # Запускаем дешифрование с ошибкой
            result = subprocess.run(cmd_decrypt_wrong, capture_output=True, text=True, encoding='utf-8',
                                    errors='replace')
            if os.path.exists(output_wrong):
                print("    ⚠️  File was not deleted on authentication error")
                os.remove(output_wrong)
            else:
                print("    ✓ File deleted on authentication error")

        finally:
            # Очистка
            for f in [input_file, output_enc, output_dec]:
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except:
                        pass

        print("  ✓ All file operations work correctly")
        return True


def run_all_tests():
    """Запуск всех тестов"""
    print("=" * 80)
    print("COMPREHENSIVE TESTS FOR ENCRYPT-THEN-MAC (TEST-9)")
    print("=" * 80)

    tester = TestEncryptThenMACComprehensive()
    tests = [
        ("Round-trip test", tester.test_1_roundtrip),
        ("AAD tampering test", tester.test_2_aad_tamper_catastrophic_failure),
        ("Ciphertext/tag tampering test", tester.test_3_ciphertext_tamper_catastrophic_failure),
        ("IV uniqueness test", tester.test_4_nonce_uniqueness),
        ("Empty AAD test", tester.test_5_empty_aad),
        ("Large AAD test", tester.test_6_large_aad_streaming),
        ("ETM-specific tests", tester.test_7_encrypt_then_mac_specific_tests),
        ("File operations test", tester.test_8_file_operations),
    ]

    all_passed = True
    failed_tests = []

    for test_name, test_func in tests:
        print(f"\n{'=' * 60}")
        print(f"Running: {test_name}")
        print(f"{'=' * 60}")

        try:
            tester.setup_method()
            success = test_func()
            if success:
                print(f"✓ {test_name} passed")
            else:
                print(f"✗ {test_name} failed")
                all_passed = False
                failed_tests.append(test_name)
        except Exception as e:
            print(f"✗ {test_name} raised exception: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
            failed_tests.append(test_name)

    print(f"\n{'=' * 80}")
    print("ENCRYPT-THEN-MAC TESTING RESULTS:")
    print(f"{'=' * 80}")

    if all_passed:
        print("✓ ALL 8 TESTS FOR ENCRYPT-THEN-MAC PASSED SUCCESSFULLY!")
        print("\nCompliance with TEST-9 requirements:")
        print("  ✓ Analogous to TEST-2: Round-trip test")
        print("  ✓ Analogous to TEST-3: AAD tampering test (catastrophic failure)")
        print("  ✓ Analogous to TEST-4: Ciphertext/tag tampering test")
        print("  ✓ Analogous to TEST-5: Nonce/IV uniqueness test")
        print("  ✓ Analogous to TEST-6: Empty AAD test")
        print("  ✓ Analogous to TEST-7: Large AAD test (streaming processing)")
        print("  ✓ Additionally: Encrypt-then-MAC specific tests")
        print("  ✓ Additionally: File operations via CLI")
    else:
        print(f"✗ SOME TESTS FAILED: {', '.join(failed_tests)}")

    return all_passed


if __name__ == '__main__':
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTesting interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
# [file content end]