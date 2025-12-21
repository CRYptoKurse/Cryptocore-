# [file name]: cryptocore.py (обновленная версия с поддержкой ETM)
# [file content begin]
import sys
import argparse
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from csprng import generate_random_bytes

# Импортируем наши реализации
from sha256 import SHA256
from sha3_256 import SHA3_256
from mac.hmac import HMAC
from modes.gcm import GCM, AuthenticationError as GCMAuthenticationError
from aead.encrypt_then_mac import EncryptThenMAC, AuthenticationError as ETMAuthenticationError


class CryptoCore:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.block_size = AES.block_size  # 16 bytes for AES

    def _validate_key(self, key_hex: str) -> bytes:
        """Проверка и преобразование ключа из hex строки"""
        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) not in [16, 24, 32]:
                raise ValueError("Длина ключа должна быть 16, 24 или 32 байта")
            return key_bytes
        except ValueError as e:
            print(f"Ошибка в формате ключа: {e}", file=sys.stderr)
            sys.exit(1)

    def _validate_iv(self, iv_hex: str) -> bytes:
        """Проверка и преобразование IV/nonce из hex строки"""
        try:
            iv_bytes = bytes.fromhex(iv_hex)
            return iv_bytes
        except ValueError as e:
            print(f"Ошибка в формате IV/nonce: {e}", file=sys.stderr)
            sys.exit(1)

    def _generate_iv(self, mode: str) -> bytes:
        """Генерация случайного IV/nonce с использованием CSPRNG"""
        if mode == 'gcm':
            return generate_random_bytes(12)  # 12-байтовый nonce для GCM
        else:
            return generate_random_bytes(16)  # 16-байтовый IV для других режимов

    def _read_file(self, file_path: str) -> bytes:
        """Чтение файла с обработкой ошибок"""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Ошибка чтения файла {file_path}: {e}", file=sys.stderr)
            sys.exit(1)

    def _write_file(self, file_path: str, data: bytes):
        """Запись файла с обработкой ошибок"""
        try:
            with open(file_path, 'wb') as f:
                f.write(data)
        except Exception as e:
            print(f"Ошибка записи файла {file_path}: {e}", file=sys.stderr)
            sys.exit(1)

    def _remove_file(self, file_path: str):
        """Удаление файла при ошибке аутентификации"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """Побитовый XOR двух байтовых строк одинаковой длины"""
        return bytes(x ^ y for x, y in zip(a, b))

    # Реализация режимов "с нуля" для Спринта 2
    def _process_ecb(self, data: bytes, key: bytes, encrypt: bool) -> bytes:
        """Самостоятельная реализация ECB режима с PKCS#7 padding"""
        cipher = AES.new(key, AES.MODE_ECB)

        if encrypt:
            # Дополнение PKCS#7
            data = pad(data, self.block_size)

            # Шифрование каждого блока по отдельности
            encrypted_blocks = []
            for i in range(0, len(data), self.block_size):
                block = data[i:i + self.block_size]
                encrypted_block = cipher.encrypt(block)
                encrypted_blocks.append(encrypted_block)

            return b''.join(encrypted_blocks)
        else:
            # Дешифрование каждого блока по отдельности
            decrypted_blocks = []
            for i in range(0, len(data), self.block_size):
                block = data[i:i + self.block_size]
                decrypted_block = cipher.decrypt(block)
                decrypted_blocks.append(decrypted_block)

            decrypted_data = b''.join(decrypted_blocks)
            # Удаление дополнения PKCS#7
            return unpad(decrypted_data, self.block_size)

    def _process_cbc(self, data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        """Самостоятельная реализация CBC режима с PKCS#7 padding"""
        cipher = AES.new(key, AES.MODE_ECB)

        if encrypt:
            # Дополнение PKCS#7
            data = pad(data, self.block_size)

            blocks = []
            previous = iv

            for i in range(0, len(data), self.block_size):
                block = data[i:i + self.block_size]
                # XOR с предыдущим шифртекстом (или IV для первого блока)
                xored = self._xor_bytes(block, previous)
                # Шифрование
                encrypted = cipher.encrypt(xored)
                blocks.append(encrypted)
                previous = encrypted

            return b''.join(blocks)
        else:
            blocks = []
            previous = iv

            for i in range(0, len(data), self.block_size):
                block = data[i:i + self.block_size]
                # Дешифрование
                decrypted = cipher.decrypt(block)
                # XOR с предыдущим шифртекстом (или IV для первого блока)
                plaintext = self._xor_bytes(decrypted, previous)
                blocks.append(plaintext)
                previous = block

            decrypted_data = b''.join(blocks)
            # Удаление дополнения PKCS#7
            return unpad(decrypted_data, self.block_size)

    def _process_cfb(self, data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        """Самостоятельная реализация CFB режима (без дополнения)"""
        cipher = AES.new(key, AES.MODE_ECB)
        result = bytearray()
        feedback = iv

        # CFB режим работает с полными блоками
        for i in range(0, len(data), self.block_size):
            # Шифруем feedback
            encrypted_feedback = cipher.encrypt(feedback)

            block = data[i:i + self.block_size]
            # Если блок неполный (последний блок)
            if len(block) < self.block_size:
                # Используем только нужное количество байт из encrypted_feedback
                encrypted_feedback = encrypted_feedback[:len(block)]
                block = block.ljust(len(encrypted_feedback), b'\x00')

            if encrypt:
                # XOR открытого текста с зашифрованным feedback
                ciphertext = self._xor_bytes(block, encrypted_feedback)
                result.extend(ciphertext)
                # Для следующего блока используем ciphertext как feedback
                feedback = ciphertext.ljust(self.block_size, b'\x00')
            else:
                # XOR шифртекста с зашифрованным feedback
                plaintext = self._xor_bytes(block, encrypted_feedback)
                result.extend(plaintext)
                # Для следующего блока используем ciphertext (входные данные) как feedback
                feedback = block.ljust(self.block_size, b'\x00')

        # Убираем лишние нули, добавленные для выравнивания
        return bytes(result[:len(data)])

    def _process_ofb(self, data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        """Самостоятельная реализация OFB режима (без дополнения)"""
        cipher = AES.new(key, AES.MODE_ECB)
        result = bytearray()
        keystream = iv

        for i in range(0, len(data), self.block_size):
            # Генерируем keystream
            keystream = cipher.encrypt(keystream)

            block = data[i:i + self.block_size]
            # Если блок неполный (последний блок)
            if len(block) < self.block_size:
                # Используем только нужное количество байт из keystream
                keystream_block = keystream[:len(block)]
            else:
                keystream_block = keystream

            # XOR данных с keystream (одинаково для шифрования и дешифрования)
            processed = self._xor_bytes(block, keystream_block)
            result.extend(processed)

        return bytes(result)

    def _process_ctr(self, data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        """Самостоятельная реализация CTR режима (без дополнения)"""
        cipher = AES.new(key, AES.MODE_ECB)
        result = bytearray()

        # Преобразуем IV в целое число для инкрементирования
        counter = int.from_bytes(iv, byteorder='big')

        for i in range(0, len(data), self.block_size):
            # Преобразуем текущее значение счетчика в байты
            counter_bytes = counter.to_bytes(self.block_size, byteorder='big')
            # Шифруем счетчик
            keystream_block = cipher.encrypt(counter_bytes)

            block = data[i:i + self.block_size]
            # Если блок неполный (последний блок)
            if len(block) < self.block_size:
                # Используем только нужное количество байт из keystream
                keystream_block = keystream_block[:len(block)]

            # XOR данных с keystream (одинаково для шифрования и дешифрования)
            processed = self._xor_bytes(block, keystream_block)
            result.extend(processed)

            # Инкрементируем счетчик
            counter += 1

        return bytes(result)

    def _process_gcm(self, data: bytes, key: bytes, iv: bytes, aad: bytes, encrypt: bool) -> bytes:
        """
        Обработка GCM режима

        Аргументы:
            data: входные данные
            key: ключ AES
            iv: одноразовый номер (12 байт)
            aad: ассоциированные данные
            encrypt: True для шифрования, False для дешифрования

        Возвращает:
            Обработанные данные
        """
        gcm = GCM(key, iv)

        if encrypt:
            return gcm.encrypt(data, aad)
        else:
            return gcm.decrypt(data, aad)

    def _process_etm(self, data: bytes, key: bytes, iv: bytes, aad: bytes, encrypt: bool) -> bytes:
        """
        Обработка Encrypt-then-MAC режима

        Аргументы:
            data: входные данные
            key: ключ (минимум 32 байта для AES-128 + HMAC)
            iv: вектор инициализации (16 байт)
            aad: ассоциированные данные
            encrypt: True для шифрования, False для дешифрования

        Возвращает:
            Обработанные данные
        """
        # Проверка длины ключа для etm
        if len(key) < 32:
            raise ValueError("Для режима etm требуется ключ минимум 32 байта")

        etm = EncryptThenMAC(key, mode='ctr', hash_algorithm='sha256')

        if encrypt:
            return etm.encrypt(data, aad, iv)
        else:
            return etm.decrypt(data, aad)

    def process_file(self, algorithm: str, mode: str, operation: str,
                     key_hex: str = None, input_file: str = None,
                     output_file: str = None, iv_hex: str = None,
                     aad_hex: str = None):
        """Основной метод обработки файла"""

        # Валидация аргументов
        if algorithm != 'aes':
            print("Ошибка: поддерживается только алгоритм 'aes'", file=sys.stderr)
            sys.exit(1)

        supported_modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm', 'etm']
        if mode not in supported_modes:
            print(f"Ошибка: поддерживаются только режимы {supported_modes}", file=sys.stderr)
            sys.exit(1)

        # Определение операции
        is_encrypt = (operation == 'encrypt')

        # Обработка ключа
        if is_encrypt:
            if key_hex:
                # Использовать предоставленный ключ
                key = self._validate_key(key_hex)
            else:
                # Сгенерировать ключ (для etm - минимум 32 байта)
                try:
                    if mode == 'etm':
                        key = generate_random_bytes(32)  # 32 байта для AES-128 + HMAC
                    else:
                        key = generate_random_bytes(16)
                    key_hex = key.hex()
                    if self.verbose:
                        print(f"[INFO] Сгенерирован случайный ключ: {key_hex}")
                except Exception as e:
                    print(f"Ошибка генерации ключа: {e}", file=sys.stderr)
                    sys.exit(1)
        else:
            # Дешифрование: ключ обязателен
            if not key_hex:
                print("Ошибка: для дешифрования требуется аргумент --key", file=sys.stderr)
                sys.exit(1)
            key = self._validate_key(key_hex)

        # Обработка AAD
        aad = b""
        if aad_hex:
            try:
                aad = bytes.fromhex(aad_hex)
                if self.verbose:
                    print(f"[INFO] Используются ассоциированные данные: {aad_hex}")
            except ValueError as e:
                print(f"Ошибка в формате AAD: {e}", file=sys.stderr)
                sys.exit(1)

        # Чтение входных данных
        input_data = self._read_file(input_file)

        # Обработка IV/Nonce - ВАЖНОЕ ИСПРАВЛЕНИЕ
        iv = None
        if mode != 'ecb':
            # Если указан IV/nonce в аргументах, используем его
            if iv_hex:
                iv = self._validate_iv(iv_hex)
                if mode == 'gcm' and len(iv) != 12:
                    print("Ошибка: для GCM требуется 12-байтовый nonce", file=sys.stderr)
                    sys.exit(1)
                if mode != 'gcm' and len(iv) != 16:
                    print("Ошибка: для данного режима требуется 16-байтовый IV", file=sys.stderr)
                    sys.exit(1)
                if self.verbose:
                    print(f"Использован {'nonce' if mode == 'gcm' else 'IV'} из аргумента: {iv.hex()}")
            else:
                # Если IV/nonce не указан в аргументах
                if is_encrypt:
                    # При шифровании генерируем новый
                    try:
                        iv = self._generate_iv(mode)
                        if self.verbose:
                            print(f"Сгенерирован {'nonce' if mode == 'gcm' else 'IV'}: {iv.hex()}")
                    except Exception as e:
                        print(f"Ошибка генерации {'nonce' if mode == 'gcm' else 'IV'}: {e}", file=sys.stderr)
                        sys.exit(1)
                else:
                    # При дешифровании извлекаем из файла (если не указан в аргументах)
                    if mode == 'gcm':
                        extract_len = 12
                    else:
                        extract_len = 16

                    if len(input_data) < extract_len:
                        print(f"Ошибка: файл слишком короткий для извлечения {'nonce' if mode == 'gcm' else 'IV'}",
                              file=sys.stderr)
                        sys.exit(1)

                    iv = input_data[:extract_len]
                    input_data = input_data[extract_len:]

                    if self.verbose:
                        print(f"Извлечен {'nonce' if mode == 'gcm' else 'IV'} из файла: {iv.hex()}")

        # Обработка данных
        try:
            if mode == 'ecb':
                output_data = self._process_ecb(input_data, key, is_encrypt)
            elif mode == 'cbc':
                output_data = self._process_cbc(input_data, key, iv, is_encrypt)
            elif mode == 'cfb':
                output_data = self._process_cfb(input_data, key, iv, is_encrypt)
            elif mode == 'ofb':
                output_data = self._process_ofb(input_data, key, iv, is_encrypt)
            elif mode == 'ctr':
                output_data = self._process_ctr(input_data, key, iv, is_encrypt)
            elif mode == 'gcm':
                output_data = self._process_gcm(input_data, key, iv, aad, is_encrypt)
            elif mode == 'etm':
                output_data = self._process_etm(input_data, key, iv, aad, is_encrypt)
            else:
                print(f"Ошибка: неподдерживаемый режим {mode}", file=sys.stderr)
                sys.exit(1)
        except (GCMAuthenticationError, ETMAuthenticationError) as e:
            # Обработка ошибки аутентификации для GCM и ETM
            print(f"[ERROR] Authentication failed: {e}", file=sys.stderr)
            # Удаление выходного файла при ошибке аутентификации
            if output_file and os.path.exists(output_file):
                self._remove_file(output_file)
            sys.exit(1)
        except Exception as e:
            print(f"Ошибка при обработке данных: {e}", file=sys.stderr)
            sys.exit(1)

        # Добавление IV/nonce к выходным данным при шифровании
        # Только если IV был сгенерирован, а не взят из аргументов
        if is_encrypt and mode != 'ecb' and not iv_hex:
            output_data = iv + output_data

        # Запись результата
        self._write_file(output_file, output_data)

        if self.verbose:
            op_name = "шифрования" if is_encrypt else "дешифрования"
            print(f"[SUCCESS] Операция {op_name} успешно завершена")
            print(f"Входной файл: {input_file}")
            print(f"Выходной файл: {output_file}")
            print(f"Размер обработанных данных: {len(output_data)} байт")
            if is_encrypt and mode != 'ecb':
                if iv_hex:
                    print(f"Использован указанный {'nonce' if mode == 'gcm' else 'IV'}: {iv.hex()}")
                else:
                    print(f"Сгенерирован {'nonce' if mode == 'gcm' else 'IV'}: {iv.hex()}")

    def compute_hash(self, algorithm: str, input_file: str, output_file: str = None,
                     hmac: bool = False, key: str = None, verify_file: str = None):
        """
        Вычисление хеш-суммы или HMAC файла
        """

        if hmac:
            if not key:
                print("Ошибка: для HMAC требуется аргумент --key", file=sys.stderr)
                sys.exit(1)

            if algorithm != 'sha256':
                print("Ошибка: HMAC поддерживается только с алгоритмом sha256", file=sys.stderr)
                sys.exit(1)

            try:
                key_bytes = bytes.fromhex(key)
            except ValueError as e:
                print(f"Ошибка в формате ключа: {e}", file=sys.stderr)
                sys.exit(1)

            hmac_obj = HMAC(key_bytes, 'sha256')
            hmac_value = hmac_obj.compute_streaming(input_file)

            if verify_file:
                try:
                    with open(verify_file, 'r') as f:
                        expected_line = f.read().strip()
                        parts = expected_line.split()
                        if parts:
                            expected_hmac = parts[0]
                            if hmac_value == expected_hmac:
                                print(f"[OK] HMAC verification successful")
                                sys.exit(0)
                            else:
                                print(f"[ERROR] HMAC verification failed")
                                sys.exit(1)
                        else:
                            print(f"Ошибка: файл {verify_file} пустой или имеет неправильный формат", file=sys.stderr)
                            sys.exit(1)
                except Exception as e:
                    print(f"Ошибка чтения файла {verify_file}: {e}", file=sys.stderr)
                    sys.exit(1)

            output_line = f"{hmac_value} {input_file}\n"

            if output_file:
                try:
                    with open(output_file, 'w') as f:
                        f.write(output_line)
                except Exception as e:
                    print(f"Ошибка записи в файл {output_file}: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                sys.stdout.write(output_line)

            return

        # Обычное хеширование
        if algorithm == 'sha256':
            hash_obj = SHA256()
        elif algorithm == 'sha3-256':
            hash_obj = SHA3_256()
        else:
            print(f"Ошибка: неподдерживаемый алгоритм хеширования '{algorithm}'", file=sys.stderr)
            sys.exit(1)

        try:
            with open(input_file, 'rb') as f:
                chunk_size = 8192
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
        except Exception as e:
            print(f"Ошибка чтения файла {input_file}: {e}", file=sys.stderr)
            sys.exit(1)

        hash_value = hash_obj.hexdigest()
        output_line = f"{hash_value} {input_file}\n"

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(output_line)
            except Exception as e:
                print(f"Ошибка записи в файл {output_file}: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            sys.stdout.write(output_line)


def main():
    parser = argparse.ArgumentParser(
        description='Утилита для шифрования/расшифрования данных и вычисления хеш-сумм',
        prog='cryptocore'
    )

    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')

    # Парсер для команды шифрования/дешифрования
    crypto_parser = subparsers.add_parser('encrypt', help='Шифрование файла')
    crypto_parser.add_argument('--decrypt', action='store_true',
                               help='Выполнить дешифрование (по умолчанию - шифрование)')
    crypto_parser.add_argument('--algorithm', required=True, choices=['aes'],
                               help='Алгоритм шифрования (только aes)')
    crypto_parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm', 'etm'],
                               help='Режим работы')
    crypto_parser.add_argument('--key', required=False,
                               help='Ключ в виде шестнадцатеричной строки (16, 24 или 32 байта)')
    crypto_parser.add_argument('--input', required=True,
                               help='Путь к входному файлу')
    crypto_parser.add_argument('--output',
                               help='Путь к выходному файлу (опционально)')
    crypto_parser.add_argument('--iv',
                               help='Вектор инициализации или одноразовый номер в виде шестнадцатеричной строки')
    crypto_parser.add_argument('--aad',
                               help='Ассоциированные данные в виде шестнадцатеричной строки (только для GCM и ETM)')
    crypto_parser.add_argument('-v', '--verbose', action='store_true',
                               help='Подробный вывод')

    # Парсер для команды хеширования
    hash_parser = subparsers.add_parser('dgst', help='Вычисление хеш-суммы или HMAC файла')
    hash_parser.add_argument('--algorithm', required=True, choices=['sha256', 'sha3-256'],
                             help='Алгоритм хеширования (sha256 или sha3-256)')
    hash_parser.add_argument('--input', required=True,
                             help='Путь к входному файлу')
    hash_parser.add_argument('--output',
                             help='Путь к выходному файлу (опционально)')
    hash_parser.add_argument('--hmac', action='store_true',
                             help='Включить режим HMAC (требует --key)')
    hash_parser.add_argument('--key',
                             help='Ключ для HMAC в виде шестнадцатеричной строки')
    hash_parser.add_argument('--verify',
                             help='Файл с ожидаемым HMAC для проверки')
    hash_parser.add_argument('-v', '--verbose', action='store_true',
                             help='Подробный вывод')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'dgst':
        crypto = CryptoCore(verbose=args.verbose)
        crypto.compute_hash(
            algorithm=args.algorithm,
            input_file=args.input,
            output_file=args.output,
            hmac=args.hmac,
            key=args.key,
            verify_file=args.verify
        )
    elif args.command == 'encrypt':
        # Проверка использования AAD только для GCM и ETM
        if args.aad and args.mode not in ['gcm', 'etm']:
            print("Предупреждение: AAD указан для режима, отличного от GCM/ETM, и будет проигнорирован",
                  file=sys.stderr)
            args.aad = None

        # Определение операции
        operation = 'decrypt' if args.decrypt else 'encrypt'

        # Генерация имени выходного файла если не указан
        if not args.output:
            if operation == 'encrypt':
                args.output = args.input + '.enc'
            else:
                # Для расшифрования удаляем .enc если есть
                if args.input.endswith('.enc'):
                    args.output = args.input[:-4] + '.dec'
                else:
                    args.output = args.input + '.dec'
            if args.verbose:
                print(f"Выходной файл не указан, используется: {args.output}")

        # Проверка для GCM дешифрования
        if args.mode == 'gcm' and args.decrypt and not args.iv and args.input:
            # Для GCM дешифрования nonce извлекается из файла
            try:
                with open(args.input, 'rb') as f:
                    # Проверяем, что файл содержит как минимум nonce (12 байт)
                    f.seek(0, 2)
                    file_size = f.tell()
                    if file_size < 12:
                        print("Ошибка: входной файл слишком короткий для GCM", file=sys.stderr)
                        sys.exit(1)
            except Exception as e:
                print(f"Ошибка проверки файла: {e}", file=sys.stderr)
                sys.exit(1)

        # Проверка длины ключа для ETM
        if args.mode == 'etm' and args.key:
            try:
                key_bytes = bytes.fromhex(args.key)
                if len(key_bytes) < 32:
                    print("Предупреждение: для режима ETM рекомендуется использовать ключ минимум 32 байта",
                          file=sys.stderr)
            except ValueError:
                pass  # Ошибка будет обработана позже

        # Создание экземпляра и обработка
        crypto = CryptoCore(verbose=args.verbose)
        crypto.process_file(
            algorithm=args.algorithm,
            mode=args.mode,
            operation=operation,
            key_hex=args.key,
            input_file=args.input,
            output_file=args.output,
            iv_hex=args.iv,
            aad_hex=args.aad
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
# [file content end]