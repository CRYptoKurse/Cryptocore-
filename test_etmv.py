# [file name]: test_encrypt_then_mac.py
# [file content begin]
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aead.encrypt_then_mac import EncryptThenMAC, AuthenticationError


def test_encrypt_then_mac():
    """Тестирование реализации Encrypt-then-MAC"""
    
    print("Тестирование Encrypt-then-MAC...")
    
    # Тест 1: Базовое шифрование/дешифрование
    print("\nТест 1: Базовое шифрование/дешифрование")
    key = os.urandom(32)  # 16 для AES-128 + 16 для HMAC
    plaintext = b"Secret message for testing"
    aad = b"Associated data"
    
    etm = EncryptThenMAC(key, mode='ctr')
    ciphertext = etm.encrypt(plaintext, aad)
    decrypted = etm.decrypt(ciphertext, aad)
    
    assert decrypted == plaintext, "Ошибка базового шифрования/дешифрования"
    print("✓ Тест 1 пройден")
    
    # Тест 2: Проверка аутентификации (правильный AAD)
    print("\nТест 2: Проверка аутентификации с правильным AAD")
    try:
        decrypted = etm.decrypt(ciphertext, aad)
        print("✓ Тест 2 пройден (аутентификация успешна)")
    except AuthenticationError:
        assert False, "Аутентификация не должна была завершиться ошибкой"
    
    # Тест 3: Проверка аутентификации (неправильный AAD)
    print("\nТест 3: Проверка аутентификации с неправильным AAD")
    wrong_aad = b"Wrong associated data"
    try:
        decrypted = etm.decrypt(ciphertext, wrong_aad)
        assert False, "Аутентификация должна была завершиться ошибкой"
    except AuthenticationError as e:
        print(f"✓ Тест 3 пройден (ожидаемая ошибка: {e})")
    
    # Тест 4: Искажение шифртекста
    print("\nТест 4: Искажение шифртекста")
    tampered = bytearray(ciphertext)
    tampered[30] ^= 0x01  # Изменяем один байт в шифртексте
    try:
        decrypted = etm.decrypt(bytes(tampered), aad)
        assert False, "Аутентификация должна была завершиться ошибкой"
    except AuthenticationError as e:
        print(f"✓ Тест 4 пройден (ожидаемая ошибка: {e})")
    
    # Тест 5: Искажение тега
    print("\nТест 5: Искажение тега")
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01  # Изменяем последний байт тега
    try:
        decrypted = etm.decrypt(bytes(tampered), aad)
        assert False, "Аутентификация должна была завершиться ошибкой"
    except AuthenticationError as e:
        print(f"✓ Тест 5 пройден (ожидаемая ошибка: {e})")
    
    # Тест 6: Пустые данные
    print("\nТест 6: Пустые данные")
    plaintext = b""
    aad = b""
    ciphertext = etm.encrypt(plaintext, aad)
    decrypted = etm.decrypt(ciphertext, aad)
    assert decrypted == plaintext, "Ошибка с пустыми данными"
    print("✓ Тест 6 пройден")
    
    # Тест 7: Большие данные
    print("\nТест 7: Большие данные")
    plaintext = os.urandom(10000)
    aad = os.urandom(500)
    ciphertext = etm.encrypt(plaintext, aad)
    decrypted = etm.decrypt(ciphertext, aad)
    assert decrypted == plaintext, "Ошибка с большими данными"
    print("✓ Тест 7 пройден")
    
    # Тест 8: Режим CBC
    print("\nТест 8: Режим CBC")
    etm_cbc = EncryptThenMAC(key, mode='cbc')
    plaintext = b"Test with CBC mode"
    aad = b"CBC associated data"
    ciphertext = etm_cbc.encrypt(plaintext, aad)
    decrypted = etm_cbc.decrypt(ciphertext, aad)
    assert decrypted == plaintext, "Ошибка с режимом CBC"
    print("✓ Тест 8 пройден")
    
    print("\n✅ Все тесты Encrypt-then-MAC пройдены успешно!")
    return True


if __name__ == '__main__':
    try:
        test_encrypt_then_mac()
    except AssertionError as e:
        print(f"\n❌ Тест не пройден: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        sys.exit(1)
# [file content end]