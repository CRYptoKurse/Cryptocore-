Отчет по реализации Спринта 1: CryptoCore
1. Обзор проекта
Название проекта: CryptoCore - утилита для шифрования и расшифрования данных
Язык реализации: Python
Базовые криптографические примитивы: cryptography
Режим работы: ECB
Стандарт дополнения: PKCS#7
Формат ключа: Шестнадцатеричная строка (16 байт для AES-128)

2. Реализованные требования
STR-1: Репозиторий Git ✓
Проект размещен в Git-репозитории с соответствующей структурой файлов.

STR-2: Файл README.md ✓
Содержит:

Название проекта и описание

Инструкции по сборке

Инструкции по использованию

Список зависимостей

STR-3: Система сборки ✓
Созданы файлы:

requirements.txt - список зависимостей

Структура проекта организована логично

CLI-1: Вызов инструмента ✓
Инструмент вызывается как cryptocore:

python
parser = argparse.ArgumentParser(
    description='Утилита для шифрования и расшифрования данных AES-128 ECB',
    prog='cryptocore'  # <- Реализация CLI-1
)
CLI-2: Аргументы командной строки ✓
Реализованы все обязательные аргументы:

python
# Обязательные аргументы согласно CLI-2
parser.add_argument('--algorithm', required=True, choices=['aes'],
                   help='Алгоритм шифрования (только aes)')
parser.add_argument('--mode', required=True, choices=['ecb'],
                   help='Режим работы (только ecb)')

# Взаимоисключающие флаги для операции
operation_group = parser.add_mutually_exclusive_group(required=True)
operation_group.add_argument('--encrypt', action='store_true',
                           help='Выполнить шифрование')
operation_group.add_argument('--decrypt', action='store_true',
                           help='Выполнить дешифрование')

parser.add_argument('--key', required=True,
                   help='Ключ в виде шестнадцатеричной строки (16 байт)')
parser.add_argument('--input', required=True,
                   help='Путь к входному файлу')
parser.add_argument('--output',
                   help='Путь к выходному файлу (опционально)')
CLI-3: Формат ключа ✓
Ключ принимается в виде шестнадцатеричной строки:

python
def _validate_key(self, key_hex: str) -> bytes:
    """Проверка и преобразование ключа из hex строки"""
    try:
        key_bytes = bytes.fromhex(key_hex)  # <- Преобразование hex строки
        if len(key_bytes) != 16:
            raise ValueError("Ключ должен быть 16 байт для AES-128")
        return key_bytes
    except ValueError as e:
        print(f"Ошибка в формате ключа: {e}", file=sys.stderr)
        sys.exit(1)
CLI-4: Валидация аргументов ✓
Все аргументы проверяются на корректность:

python
# Валидация аргументов в методе process_file
if algorithm != 'aes':
    print("Ошибка: поддерживается только алгоритм 'aes'", file=sys.stderr)
    sys.exit(1)
    
if mode != 'ecb':
    print("Ошибка: поддерживается только режим 'ecb'", file=sys.stderr)
    sys.exit(1)
CLI-5: Генерация имени выходного файла ✓
Если выходной файл не указан, генерируется автоматически:

python
# Генерация имени выходного файла если не указан (CLI-5)
if not args.output:
    if operation == 'encrypt':
        args.output = args.input + '.enc'
    else:
        args.output = args.input + '.dec'
CRY-1: AES-128 ✓
Используется AES-128 с 16-байтным ключом:

python
key_bytes = bytes.fromhex(key_hex)
if len(key_bytes) != 16:
    raise ValueError("Ключ должен быть 16 байт для AES-128")
CRY-2: Использование криптобиблиотеки ✓
Используется библиотека cryptography вместо реализации с нуля:

python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Создание шифра с использованием библиотеки
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
CRY-3: Логика режима ECB ✓
Реализована логика разделения на блоки и обработки ECB:

python
def _process_ecb(self, data: bytes, key: bytes, encrypt: bool) -> bytes:
    """Обработка данных в режиме ECB с PKCS#7 padding"""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    
    if encrypt:
        # Дополнение и шифрование
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()
    else:
        # Дешифрование и удаление дополнения
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
CRY-4: Дополнение PKCS#7 ✓
Реализовано стандартное дополнение PKCS#7:

python
# При шифровании
padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

# При дешифровании
unpadder = padding.PKCS7(128).unpadder()
return unpadder.update(decrypted_data) + unpadder.finalize()
CRY-5: Обработка бинарных файлов ✓
Файлы читаются и записываются в бинарном режиме:

python
def _read_file(self, file_path: str) -> bytes:
    """Чтение файла с обработкой ошибок"""
    try:
        with open(file_path, 'rb') as f:  # <- Бинарный режим чтения
            return f.read()

def _write_file(self, file_path: str, data: bytes):
    """Запись файла с обработкой ошибок"""
    try:
        with open(file_path, 'wb') as f:  # <- Бинарный режим записи
            f.write(data)
IO-1: Чтение файла ✓
Весь файл читается полностью:

python
with open(file_path, 'rb') as f:
    return f.read()  # <- Чтение всего файла
IO-2: Запись файла ✓
Результат записывается в выходной файл:

python
with open(file_path, 'wb') as f:
    f.write(data)  # <- Запись всех данных
IO-3: Обработка ошибок файлов ✓
Реализована обработка файловых ошибок:

python
try:
    with open(file_path, 'rb') as f:
        return f.read()
except Exception as e:
    print(f"Ошибка чтения файла {file_path}: {e}", file=sys.stderr)  # <- stderr
    sys.exit(1)  # <- Ненулевой код состояния
3. Примеры использования
Пример 1: Шифрование файла
bash
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin
Пример 2: Дешифрование файла
bash
cryptocore --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt
Пример 3: Автоматическое именование выходного файла
bash
# Выходной файл будет plaintext.txt.enc
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt
4. Тестирование
TEST-1: Циклическое тестирование ✓
Реализована возможность шифрования с последующим дешифрованием:

bash
# Шифрование
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input original.txt --output encrypted.bin

# Дешифрование
cryptocore --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input encrypted.bin --output decrypted.txt

# Проверка
diff original.txt decrypted.txt  # Файлы идентичны
TEST-2: Скрипт тестирования
В README.md представлен пример циклического теста.

5. Структура проекта
text
project_root/
├── Core.py          # Основной файл программы
├── requirements.txt       # Зависимости проекта
├── README.md             # Документация
└── test.py        # Скрипт для автоматического тестирования
6. Зависимости
txt
cryptography>=3.4.8
7. Заключение
Все обязательные требования спринта 1 выполнены. Реализована полностью функциональная утилита командной строки для шифрования и дешифрования данных с использованием AES-128 в режиме ECB. Код соответствует всем техническим требованиям, включает обработку ошибок, валидацию входных данных и поддержку стандартного дополнения PKCS#7.
