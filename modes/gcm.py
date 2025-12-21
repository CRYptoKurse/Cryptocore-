# [file name]: modes/gcm.py
# [file content begin]
import os
from Crypto.Cipher import AES


class AuthenticationError(Exception):
    """Исключение для ошибок аутентификации"""
    pass


class GCM:
    def __init__(self, key, nonce=None):
        """
        Инициализация GCM

        Аргументы:
            key: ключ AES (16, 24 или 32 байта)
            nonce: одноразовый номер (12 байт рекомендуется)
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Длина ключа должна быть 16, 24 или 32 байта")

        self.key = key
        self.aes = AES.new(key, AES.MODE_ECB)
        self.nonce = nonce or os.urandom(12)

        if len(self.nonce) != 12:
            # Для nonce другой длины требуется GHASH
            raise NotImplementedError("Только 12-байтовый nonce поддерживается")

        # Константа для умножения в поле Галуа
        self.R = 0xE1000000000000000000000000000000

        # Предвычисление H = E(K, 0^128)
        self.H = int.from_bytes(self.aes.encrypt(b'\x00' * 16), 'big')

        # Предвычисление таблицы умножения для GHASH
        self._precompute_table()

    def _precompute_table(self):
        """Предвычисление таблицы для умножения в GF(2^128)"""
        self.M_table = [0] * 16
        self.M_table[0] = self.H

        for i in range(1, 16):
            self.M_table[i] = self._mult_gf(self.M_table[i-1], self.H)

    def _mult_gf(self, x, y):
        """
        Умножение в GF(2^128) с использованием неприводимого полинома
        x^128 + x^7 + x^2 + x + 1
        """
        z = 0
        v = y

        # x и y - 128-битные целые числа
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            # Умножение на x (сдвиг вправо) с учетом полинома
            if v & 1:
                v = (v >> 1) ^ self.R
            else:
                v >>= 1

        return z

    def _ghash(self, aad, ciphertext):
        """
        Вычислить GHASH в GF(2^128)

        Формат: GHASH(H, A, C) = X_{m+n+1}
        где A - ассоциированные данные, C - шифротекст
        """
        # Подготовка данных
        len_aad = len(aad)
        len_ciphertext = len(ciphertext)

        # Дополнение до кратного 16 байтам
        aad_padded = aad + b'\x00' * ((-len_aad) % 16)
        ciphertext_padded = ciphertext + b'\x00' * ((-len_ciphertext) % 16)

        # Инициализация Y0 = 0
        y = 0

        # Обработка AAD
        for i in range(0, len(aad_padded), 16):
            block = aad_padded[i:i+16]
            block_int = int.from_bytes(block, 'big')
            y = self._mult_gf(y ^ block_int, self.H)

        # Обработка шифротекста
        for i in range(0, len(ciphertext_padded), 16):
            block = ciphertext_padded[i:i+16]
            block_int = int.from_bytes(block, 'big')
            y = self._mult_gf(y ^ block_int, self.H)

        # Добавление длины AAD и шифротекста (в битах)
        len_block = ((len_aad * 8) << 64) | (len_ciphertext * 8)
        len_bytes = len_block.to_bytes(16, 'big')
        len_int = int.from_bytes(len_bytes, 'big')

        y = self._mult_gf(y ^ len_int, self.H)

        return y.to_bytes(16, 'big')

    def _gctr(self, icb, plaintext):
        """
        Режим GCTR (GCM Counter Mode)

        Аргументы:
            icb: начальное значение счетчика
            plaintext: открытый текст для шифрования
        """
        if not plaintext:
            return b''

        n = (len(plaintext) + 15) // 16  # Количество блоков
        ciphertext = bytearray()

        for i in range(n):
            # Формирование счетчика (инкремент только последние 32 бита)
            if i > 0:
                # Инкрементируем последние 32 бита
                icb_int = int.from_bytes(icb, 'big')
                icb_int = (icb_int + 1) & 0xFFFFFFFF
                icb = icb[:-4] + icb_int.to_bytes(4, 'big')

            # Шифрование счетчика
            encrypted_counter = self.aes.encrypt(icb)

            # XOR с блоком открытого текста
            block_start = i * 16
            block_end = min((i + 1) * 16, len(plaintext))
            block = plaintext[block_start:block_end]

            # Если блок неполный, используем только нужную часть
            if len(block) < 16:
                encrypted_counter = encrypted_counter[:len(block)]

            ciphertext.extend(bytes(x ^ y for x, y in zip(block, encrypted_counter)))

        return bytes(ciphertext)

    def encrypt(self, plaintext, aad=b""):
        """
        Шифрование с аутентификацией

        Аргументы:
            plaintext: открытый текст
            aad: ассоциированные данные

        Возвращает:
            nonce + шифротекст + тег (12 + len(plaintext) + 16 байт)
        """
        # Шаг 1: Подготовка счетчика J0
        if len(self.nonce) == 12:
            j0 = self.nonce + b'\x00\x00\x00\x01'
        else:
            # Для nonce другой длины требуется GHASH
            raise NotImplementedError("Только 12-байтовый nonce поддерживается")

        # Шаг 2: Шифрование в режиме GCTR
        icb = (int.from_bytes(j0, 'big') + 1).to_bytes(16, 'big')
        ciphertext = self._gctr(icb, plaintext)

        # Шаг 3: Вычисление тега аутентификации
        s = self._ghash(aad, ciphertext)
        tag = self._gctr(j0, s)

        # Шаг 4: Формирование результата
        return self.nonce + ciphertext + tag[:16]

    def decrypt(self, data, aad=b""):
        """
        Дешифрование с проверкой аутентификации

        Аргументы:
            data: данные в формате nonce + шифротекст + тег
            aad: ассоциированные данные

        Возвращает:
            открытый текст

        Исключения:
            AuthenticationError: если проверка аутентификации не удалась
        """
        # Извлечение компонентов
        if len(data) < 28:  # Минимум: 12 nonce + 0 ciphertext + 16 tag
            raise AuthenticationError("Данные слишком короткие")

        nonce = data[:12]
        ciphertext = data[12:-16]
        tag = data[-16:]

        # Восстановление объекта с тем же nonce
        self.nonce = nonce

        # Подготовка счетчика J0
        if len(self.nonce) == 12:
            j0 = self.nonce + b'\x00\x00\x00\x01'
        else:
            raise NotImplementedError("Только 12-байтовый nonce поддерживается")

        # Проверка тега
        s = self._ghash(aad, ciphertext)
        expected_tag = self._gctr(j0, s)[:16]

        if tag != expected_tag:
            raise AuthenticationError("Проверка аутентификации не удалась: неверный AAD или искаженные данные")

        # Дешифрование
        icb = (int.from_bytes(j0, 'big') + 1).to_bytes(16, 'big')
        plaintext = self._gctr(icb, ciphertext)

        return plaintext
# [file content end]