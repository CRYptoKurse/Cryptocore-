# [file name]: mac/hmac.py
# [file content begin]
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sha256 import SHA256


class HMAC:
    def __init__(self, key: bytes, hash_function='sha256'):
        """
        Инициализация HMAC с использованием ключа.

        Аргументы:
            key: ключ в виде байтов
            hash_function: используемая хеш-функция (поддерживается только 'sha256')
        """
        if hash_function != 'sha256':
            raise ValueError("Only sha256 is supported for HMAC")
        self.hash_class = SHA256
        self.block_size = 64  # байт, для SHA-256
        self.key = self._process_key(key)

    def _process_key(self, key: bytes) -> bytes:
        """
        Обработка ключа согласно RFC 2104:
        - Если ключ длиннее размера блока, хешируем его
        - Если ключ короче, дополняем нулями
        """
        # Если ключ длиннее размера блока, хешируем его
        if len(key) > self.block_size:
            hash_obj = self.hash_class()
            hash_obj.update(key)
            key = hash_obj.digest()

        # Если ключ короче, дополняем нулями
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))

        return key

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """Побитовый XOR двух байтовых строк одинаковой длины"""
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message: bytes) -> str:
        """
        Вычисление HMAC для сообщения.

        Формула: HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))

        Возвращает:
            HMAC в виде шестнадцатеричной строки
        """
        # Создаем внутреннюю и внешнюю "подложки" (pads)
        ipad = b'\x36' * self.block_size
        opad = b'\x5c' * self.block_size

        # Вычисляем K ⊕ ipad и K ⊕ opad
        k_ipad = self._xor_bytes(self.key, ipad)
        k_opad = self._xor_bytes(self.key, opad)

        # Внутренний хеш: H((K ⊕ ipad) ∥ message)
        inner_hash_obj = self.hash_class()
        inner_hash_obj.update(k_ipad)
        inner_hash_obj.update(message)
        inner_hash = inner_hash_obj.digest()

        # Внешний хеш: H((K ⊕ opad) ∥ inner_hash)
        outer_hash_obj = self.hash_class()
        outer_hash_obj.update(k_opad)
        outer_hash_obj.update(inner_hash)

        return outer_hash_obj.hexdigest()

    def compute_bytes(self, message: bytes) -> bytes:
        """
        Вычисление HMAC для сообщения с возвратом в виде байтов.

        Формула: HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))

        Возвращает:
            HMAC в виде байтов
        """
        # Создаем внутреннюю и внешнюю "подложки" (pads)
        ipad = b'\x36' * self.block_size
        opad = b'\x5c' * self.block_size

        # Вычисляем K ⊕ ipad и K ⊕ opad
        k_ipad = self._xor_bytes(self.key, ipad)
        k_opad = self._xor_bytes(self.key, opad)

        # Внутренний хеш: H((K ⊕ ipad) ∥ message)
        inner_hash_obj = self.hash_class()
        inner_hash_obj.update(k_ipad)
        inner_hash_obj.update(message)
        inner_hash = inner_hash_obj.digest()

        # Внешний хеш: H((K ⊕ opad) ∥ inner_hash)
        outer_hash_obj = self.hash_class()
        outer_hash_obj.update(k_opad)
        outer_hash_obj.update(inner_hash)

        return outer_hash_obj.digest()

    def compute_streaming(self, input_file: str) -> str:
        """
        Вычисление HMAC для файла с потоковой обработкой.

        Аргументы:
            input_file: путь к входному файлу

        Возвращает:
            HMAC в виде шестнадцатеричной строки
        """
        # Создаем внутреннюю и внешнюю "подложки" (pads)
        ipad = b'\x36' * self.block_size
        opad = b'\x5c' * self.block_size

        # Вычисляем K ⊕ ipad и K ⊕ opad
        k_ipad = self._xor_bytes(self.key, ipad)
        k_opad = self._xor_bytes(self.key, opad)

        # Внутренний хеш: H((K ⊕ ipad) ∥ message)
        inner_hash_obj = self.hash_class()
        inner_hash_obj.update(k_ipad)

        # Чтение файла по частям
        try:
            with open(input_file, 'rb') as f:
                chunk_size = 8192  # 8KB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    inner_hash_obj.update(chunk)
        except Exception as e:
            print(f"Ошибка чтения файла {input_file}: {e}", file=sys.stderr)
            sys.exit(1)

        inner_hash = inner_hash_obj.digest()

        # Внешний хеш: H((K ⊕ opad) ∥ inner_hash)
        outer_hash_obj = self.hash_class()
        outer_hash_obj.update(k_opad)
        outer_hash_obj.update(inner_hash)

        return outer_hash_obj.hexdigest()
# [file content end]