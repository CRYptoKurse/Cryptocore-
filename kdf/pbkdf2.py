# [file name]: src/kdf/pbkdf2.py
# [file content begin]
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mac.hmac import HMAC


def pbkdf2_hmac_sha256(password, salt, iterations, dklen):
    """
    Реализация PBKDF2-HMAC-SHA256 согласно RFC 2898.

    Args:
        password: пароль (bytes или str)
        salt: соль (bytes или str hex)
        iterations: количество итераций
        dklen: длина производного ключа в байтах

    Returns:
        Производный ключ как bytes
    """
    # Преобразование пароля в байты
    if isinstance(password, str):
        password = password.encode('utf-8')

    # Преобразование соли в байты
    if isinstance(salt, str):
        # Проверяем, является ли строка hex
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            # Если не hex, обрабатываем как обычную строку
            salt = salt.encode('utf-8')

    # Размер блока HMAC-SHA256 (32 байта для SHA-256)
    hlen = 32
    # Количество необходимых блоков
    l = (dklen + hlen - 1) // hlen

    derived_key = b''

    for i in range(1, l + 1):
        # Вычисляем U1 = HMAC(password, salt || INT_32_BE(i))
        block_salt = salt + i.to_bytes(4, 'big')
        hmac = HMAC(password, 'sha256')
        u_prev = hmac.compute_bytes(block_salt)
        block = u_prev

        # Вычисляем U2..Uc и выполняем XOR
        for _ in range(2, iterations + 1):
            hmac = HMAC(password, 'sha256')
            u_curr = hmac.compute_bytes(u_prev)
            # XOR текущего U с блоком
            block = bytes(a ^ b for a, b in zip(block, u_curr))
            u_prev = u_curr

        derived_key += block

    # Возвращаем ровно dklen байт
    return derived_key[:dklen]


# Тестовые векторы для проверки
if __name__ == "__main__":
    print("Тест 1: Простой тест PBKDF2")
    result = pbkdf2_hmac_sha256(b'test', b'salt', 1, 32)
    print(f"Длина результата: {len(result)} байт")
    print(f"Результат: {result.hex()[:64]}...")

    print("\nТест 2: Проверка детерминированности")
    r1 = pbkdf2_hmac_sha256(b'password', b'salt', 1000, 32)
    r2 = pbkdf2_hmac_sha256(b'password', b'salt', 1000, 32)
    print(f"Результаты совпадают: {r1 == r2}")

    print("\nТест 3: Различные длины")
    for length in [1, 16, 32, 64]:
        result = pbkdf2_hmac_sha256(b'test', b'salt', 1, length)
        print(f"Длина {length}: {len(result)} байт")
# [file content end]