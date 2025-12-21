# Документация API CryptoCore

## Содержание
1. [Обзор](#обзор)
2. [Модуль: csprng](#модуль-csprng)
3. [Модуль: hash](#модуль-hash)
4. [Модуль: mac](#модуль-mac)
5. [Модуль: kdf](#модуль-kdf)
6. [Модуль: modes](#модуль-modes)
7. [Модуль: cryptocore](#модуль-cryptocore)
8. [Безопасность](#безопасность)

## Обзор

CryptoCore — это криптографическая библиотека, реализующая основные алгоритмы симметричного шифрования, хеширования и выработки ключей.

## Модуль: csprng

### `generate_random_bytes(num_bytes: int) -> bytes`
Генерирует криптографически стойкую случайную байтовую строку.

**Параметры:**
- `num_bytes` (int): количество байт для генерации (1-65536)

**Возвращает:**
- `bytes`: случайная байтовая строка указанной длины

**Исключения:**
- `RuntimeError`: если генерация не удалась

**Пример:**
```python
from csprng import generate_random_bytes

random_bytes = generate_random_bytes(32)
print(f"Случайные байты: {random_bytes.hex()}")
Модуль: hash
Класс: SHA256
Реализация SHA-256 (FIPS 180-4).

__init__()
Инициализирует объект SHA-256.

update(message: bytes) -> None
Добавляет данные для хеширования.

Параметры:

message (bytes): данные для добавления

digest() -> bytes
Возвращает хеш в виде байтов.

Возвращает:

bytes: 32-байтовый хеш

hexdigest() -> str
Возвращает хеш в виде шестнадцатеричной строки.

Возвращает:

str: 64-символьная hex-строка

Класс: SHA3_256
Реализация SHA3-256 (FIPS 202).

__init__()
Инициализирует объект SHA3-256.

update(data: bytes) -> None
Обновляет хеш новыми данными.

digest() -> bytes
Возвращает финальный хеш в виде байтов.

hexdigest() -> str
Возвращает хеш в виде шестнадцатеричной строки.

Модуль: mac
Класс: HMAC
Реализация HMAC (RFC 2104).

__init__(key: bytes, hash_function: str = 'sha256')
Инициализация HMAC.

Параметры:

key (bytes): ключ для HMAC

hash_function (str): хеш-функция (только 'sha256')

compute(message: bytes) -> str
Вычисляет HMAC для сообщения.

compute_bytes(message: bytes) -> bytes
Вычисляет HMAC с возвратом в виде байтов.

compute_streaming(input_file: str) -> str
Вычисляет HMAC для файла с потоковой обработкой.

Модуль: kdf
pbkdf2_hmac_sha256(password, salt, iterations, dklen)
PBKDF2-HMAC-SHA256 (RFC 2898).

Параметры:

password (bytes/str): пароль

salt (bytes/str): соль

iterations (int): количество итераций

dklen (int): длина ключа в байтах

Возвращает:

bytes: производный ключ

derive_key(master_key: bytes, context: str, length: int = 32) -> bytes
Детерминированная выработка ключа из мастер-ключа.

Модуль: modes
Класс: GCM
Реализация GCM (NIST SP 800-38D).

__init__(key: bytes, nonce: bytes = None)
Инициализация GCM.

encrypt(plaintext: bytes, aad: bytes = b"") -> bytes
Шифрование с аутентификацией.

decrypt(data: bytes, aad: bytes = b"") -> bytes
Дешифрование с проверкой аутентификации.

Исключения:

AuthenticationError: если аутентификация не удалась

Класс: EncryptThenMAC
Реализация Encrypt-then-MAC.

__init__(key: bytes, mode: str = 'ctr', hash_algorithm: str = 'sha256')
Инициализация ETM.

encrypt(plaintext: bytes, aad: bytes = b"", iv: bytes = None) -> bytes
Шифрование с последующей MAC проверкой.

decrypt(data: bytes, aad: bytes = b"") -> bytes
Дешифрование с проверкой MAC.

Модуль: cryptocore
Класс: CryptoCore
Основной класс CLI утилиты.

process_file(algorithm, mode, operation, key_hex, input_file, output_file, iv_hex, aad_hex)
Обработка файла.

compute_hash(algorithm, input_file, output_file, hmac, key, verify_file)
Вычисление хеша или HMAC.

derive_key_from_password(...)
Выработка ключа из пароля.

Безопасность
Ключи никогда не хранятся в коде

Используется криптографически стойкий ГСЧ

Конфиденциальные данные очищаются из памяти

Аутентификация выполняется перед дешифрованием
