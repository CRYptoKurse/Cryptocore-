# [file name]: aead/encrypt_then_mac.py
# [file content begin]
import sys
import os
from Crypto.Cipher import AES


class AuthenticationError(Exception):
    """Исключение для ошибок аутентификации в Encrypt-then-MAC"""
    pass


class EncryptThenMAC:
    def __init__(self, key, mode='ctr', hash_algorithm='sha256'):
        """
        Реализация парадигмы "Шифрование-затем-MAC"
        
        Аргументы:
            key: общий ключ (минимум 32 байта: 16 для AES + 16 для HMAC)
            mode: режим шифрования ('ctr' или 'cbc')
            hash_algorithm: алгоритм хеширования ('sha256')
        """
        self.hash_algorithm = hash_algorithm
        self.mode = mode
        
        # Разделение ключей: первые N байт для шифрования, остальные для HMAC
        if len(key) < 32:
            raise ValueError("Ключ должен быть минимум 32 байта")
        
        if len(key) >= 48:  # AES-256 + HMAC
            self.enc_key = key[:32]
            self.mac_key = key[32:]
        elif len(key) >= 40:  # AES-192 + HMAC
            self.enc_key = key[:24]
            self.mac_key = key[24:]
        else:  # AES-128 + HMAC (минимальная конфигурация)
            self.enc_key = key[:16]
            self.mac_key = key[16:]
        
        # Инициализация AES шифра
        self.aes = AES.new(self.enc_key, AES.MODE_ECB)
        
        # Инициализация HMAC
        if hash_algorithm == 'sha256':
            from mac.hmac import HMAC
            self.hmac = HMAC(self.mac_key, 'sha256')
        else:
            raise ValueError(f"Неподдерживаемый алгоритм хеширования: {hash_algorithm}")
    
    def _ctr_transform(self, data, iv, encrypt=True):
        """Реализация CTR режима (аналогично cryptocore.py)"""
        counter = int.from_bytes(iv, byteorder='big')
        block_size = 16
        result = bytearray()
        
        for i in range(0, len(data), block_size):
            counter_bytes = counter.to_bytes(block_size, byteorder='big')
            keystream_block = self.aes.encrypt(counter_bytes)
            
            block = data[i:i + block_size]
            if len(block) < block_size:
                keystream_block = keystream_block[:len(block)]
            
            processed = bytes(x ^ y for x, y in zip(block, keystream_block))
            result.extend(processed)
            counter += 1
        
        return bytes(result)
    
    def _cbc_transform(self, data, iv, encrypt=True):
        """Реализация CBC режима (аналогично cryptocore.py)"""
        block_size = 16
        
        if encrypt:
            # PKCS#7 padding
            pad_len = block_size - (len(data) % block_size)
            data = data + bytes([pad_len] * pad_len)
            
            blocks = []
            previous = iv
            
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                xored = bytes(x ^ y for x, y in zip(block, previous))
                encrypted = self.aes.encrypt(xored)
                blocks.append(encrypted)
                previous = encrypted
            
            return b''.join(blocks)
        else:
            blocks = []
            previous = iv
            
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                decrypted = self.aes.decrypt(block)
                plaintext = bytes(x ^ y for x, y in zip(decrypted, previous))
                blocks.append(plaintext)
                previous = block
            
            decrypted_data = b''.join(blocks)
            # Remove PKCS#7 padding
            pad_len = decrypted_data[-1]
            return decrypted_data[:-pad_len]
    
    def encrypt(self, plaintext, aad=b"", iv=None):
        """
        Шифрование по схеме "Шифрование-затем-MAC"
        
        Формула: c = E(K_e, P), T = MAC(K_m, C | AAD), output = C | T
        
        Аргументы:
            plaintext: открытый текст
            aad: ассоциированные данные
            iv: вектор инициализации (если None, генерируется)
            
        Возвращает:
            iv + шифртекст + тег
        """
        if iv is None:
            iv = os.urandom(16)
        
        # Шаг 1: Шифрование
        if self.mode == 'ctr':
            ciphertext = self._ctr_transform(plaintext, iv, encrypt=True)
        elif self.mode == 'cbc':
            ciphertext = self._cbc_transform(plaintext, iv, encrypt=True)
        else:
            raise ValueError(f"Неподдерживаемый режим: {self.mode}")
        
        # Шаг 2: Вычисление MAC (C | AAD)
        mac_data = ciphertext + aad
        tag_hex = self.hmac.compute(mac_data)
        tag = bytes.fromhex(tag_hex)  # 32 байта для SHA-256
        
        # Шаг 3: Объединение
        return iv + ciphertext + tag
    
    def decrypt(self, data, aad=b""):
        """
        Дешифрование по схеме "Шифрование-затем-MAC"
        
        Аргументы:
            data: данные в формате iv + шифртекст + тег
            aad: ассоциированные данные
            
        Возвращает:
            открытый текст
            
        Исключения:
            AuthenticationError: если проверка MAC не удалась
        """
        # Извлечение компонентов
        iv = data[:16]
        tag = data[-32:]  # 32 байта для SHA-256 HMAC
        ciphertext = data[16:-32]
        
        # Шаг 1: Проверка MAC (C | AAD)
        mac_data = ciphertext + aad
        expected_tag_hex = self.hmac.compute(mac_data)
        expected_tag = bytes.fromhex(expected_tag_hex)
        
        if tag != expected_tag:
            raise AuthenticationError("Проверка MAC не удалась: неверный тег или искаженные данные")
        
        # Шаг 2: Дешифрование
        if self.mode == 'ctr':
            plaintext = self._ctr_transform(ciphertext, iv, encrypt=False)
        elif self.mode == 'cbc':
            plaintext = self._cbc_transform(ciphertext, iv, encrypt=False)
        else:
            raise ValueError(f"Неподдерживаемый режим: {self.mode}")
        
        return plaintext
# [file content end]