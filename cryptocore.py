# [file name]: cryptocore.py (обновленная версия)
# [file content begin]
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from csprng import generate_random_bytes
import struct
import binascii

# Импортируем наши реализации хеш-функций
from sha256 import SHA256
from sha3_256 import SHA3_256
from mac.hmac import HMAC


class CryptoCore:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.block_size = AES.block_size  # 16 bytes for AES

    def _validate_key(self, key_hex: str) -> bytes:
        """Проверка и преобразование ключа из hex строки"""
        try:
            key_bytes = bytes.fromhex(key_hex)
            return key_bytes
        except ValueError as e:
            print(f"Ошибка в формате ключа: {e}", file=sys.stderr)
            sys.exit(1)

    def _validate_iv(self, iv_hex: str) -> bytes:
        """Проверка и преобразование IV из hex строки"""
        try:
            iv_bytes = bytes.fromhex(iv_hex)
            if len(iv_bytes) != 16:
                raise ValueError("IV должен быть 16 байт")
            return iv_bytes
        except ValueError as e:
            print(f"Ошибка в формате IV: {e}", file=sys.stderr)
            sys.exit(1)

    def _generate_iv(self) -> bytes:
        """Генерация случайного IV с использованием CSPRNG"""
        return generate_random_bytes(16)

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

    def process_file(self, algorithm: str, mode: str, operation: str,
                     key_hex: str = None, input_file: str = None,
                     output_file: str = None, iv_hex: str = None):
        """Основной метод обработки файла"""

        # Валидация аргументов
        if algorithm != 'aes':
            print("Ошибка: поддерживается только алгоритм 'aes'", file=sys.stderr)
            sys.exit(1)

        supported_modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']
        if mode not in supported_modes:
            print(f"Ошибка: поддерживаются только режимы {supported_modes}", file=sys.stderr)
            sys.exit(1)

        # Определение операции
        is_encrypt = (operation == 'encrypt')

        # Обработка ключа (CLI-1, CLI-2, CLI-3)
        if is_encrypt:
            if key_hex:
                # Использовать предоставленный ключ
                key = self._validate_key(key_hex)
            else:
                # Сгенерировать ключ (CLI-3)
                try:
                    key = generate_random_bytes(16)  # KEY-1
                    key_hex = key.hex()
                    # Вывести сгенерированный ключ в stdout (CLI-3, KEY-2)
                    print(f"[INFO] Сгенерирован случайный ключ: {key_hex}")
                except Exception as e:
                    print(f"Ошибка генерации ключа: {e}", file=sys.stderr)
                    sys.exit(1)
        else:
            # Дешифрование: ключ обязателен (CLI-4)
            if not key_hex:
                print("Ошибка: для дешифрования требуется аргумент --key", file=sys.stderr)
                sys.exit(1)
            key = self._validate_key(key_hex)

        # Чтение входных данных
        input_data = self._read_file(input_file)

        # Обработка IV
        iv = None
        if mode != 'ecb':
            if is_encrypt:
                # Генерация IV при шифровании с использованием CSPRNG (IV-1)
                try:
                    iv = generate_random_bytes(16)
                    if self.verbose:
                        print(f"Сгенерирован IV: {iv.hex()}")
                except Exception as e:
                    print(f"Ошибка генерации IV: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                # Дешифрование: получение IV из аргумента или файла
                if iv_hex:
                    iv = self._validate_iv(iv_hex)
                else:
                    if len(input_data) < 16:
                        print("Ошибка: файл слишком короткий для извлечения IV", file=sys.stderr)
                        sys.exit(1)
                    iv = input_data[:16]
                    input_data = input_data[16:]
                    if self.verbose:
                        print(f"Извлечен IV из файла: {iv.hex()}")

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
            else:
                # Эта ветка не должна выполняться, так как режим уже проверен
                print(f"Ошибка: неподдерживаемый режим {mode}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Ошибка при обработке данных: {e}", file=sys.stderr)
            sys.exit(1)

        # Добавление IV к выходным данным при шифровании (IV-2)
        if is_encrypt and mode != 'ecb':
            output_data = iv + output_data

        # Запись результата
        self._write_file(output_file, output_data)

        if self.verbose:
            op_name = "шифрования" if is_encrypt else "дешифрования"
            print(f"Операция {op_name} успешно завершена")
            print(f"Входной файл: {input_file}")
            print(f"Выходной файл: {output_file}")
            print(f"Размер обработанных данных: {len(output_data)} байт")
            if is_encrypt and mode != 'ecb':
                print(f"Использован IV: {iv.hex()}")

    def compute_hash(self, algorithm: str, input_file: str, output_file: str = None,
                     hmac: bool = False, key: str = None, verify_file: str = None):
        """
        Вычисление хеш-суммы или HMAC файла
        
        Аргументы:
            algorithm: алгоритм хеширования ('sha256' или 'sha3-256')
            input_file: путь к входному файлу
            output_file: путь к выходному файлу (опционально)
            hmac: флаг использования HMAC
            key: ключ для HMAC (шестнадцатеричная строка)
            verify_file: файл с ожидаемым HMAC для проверки
        """
        
        # Проверка аргументов для HMAC (CLI-1, CLI-2)
        if hmac:
            if not key:
                print("Ошибка: для HMAC требуется аргумент --key", file=sys.stderr)
                sys.exit(1)
            
            # Проверка алгоритма для HMAC
            if algorithm != 'sha256':
                print("Ошибка: HMAC поддерживается только с алгоритмом sha256", file=sys.stderr)
                sys.exit(1)
            
            # Преобразование ключа
            try:
                key_bytes = bytes.fromhex(key)
            except ValueError as e:
                print(f"Ошибка в формате ключа: {e}", file=sys.stderr)
                sys.exit(1)
            
            # Создание HMAC объекта
            hmac_obj = HMAC(key_bytes, 'sha256')
            
            # Вычисление HMAC
            hmac_value = hmac_obj.compute_streaming(input_file)
            
            # Проверка HMAC, если указан файл для верификации (CLI-4)
            if verify_file:
                try:
                    with open(verify_file, 'r') as f:
                        # Чтение ожидаемого HMAC из файла (IO-2)
                        expected_line = f.read().strip()
                        # Разбор строки: HMAC_VALUE INPUT_FILE_PATH
                        parts = expected_line.split()
                        if parts:
                            expected_hmac = parts[0]
                            # Сравнение HMAC
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
            
            # Формирование вывода в формате: HMAC_VALUE INPUT_FILE_PATH (CLI-3)
            output_line = f"{hmac_value} {input_file}\n"
            
            if output_file:
                # Запись в файл (IO-3)
                try:
                    with open(output_file, 'w') as f:
                        f.write(output_line)
                except Exception as e:
                    print(f"Ошибка записи в файл {output_file}: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                # Вывод в stdout
                sys.stdout.write(output_line)
            
            return
        
        # Обычное хеширование (без HMAC)
        # Определяем, какой алгоритм использовать
        if algorithm == 'sha256':
            hash_obj = SHA256()
        elif algorithm == 'sha3-256':
            hash_obj = SHA3_256()
        else:
            print(f"Ошибка: неподдерживаемый алгоритм хеширования '{algorithm}'", file=sys.stderr)
            sys.exit(1)
        
        # Чтение файла в бинарном режиме (IO-1)
        try:
            with open(input_file, 'rb') as f:
                # Чтение файла частями (IO-2, HASH-5)
                chunk_size = 8192  # 8KB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
        except Exception as e:
            print(f"Ошибка чтения файла {input_file}: {e}", file=sys.stderr)
            sys.exit(1)
        
        # Получение хеша в шестнадцатеричном формате (HASH-6)
        hash_value = hash_obj.hexdigest()
        
        # Формирование вывода в формате: ХЕШ_ЗНАЧЕНИЕ ПУТЬ_К_ВХОДНОМУ_ФАЙЛУ (CLI-4)
        output_line = f"{hash_value} {input_file}\n"
        
        if output_file:
            # Запись в файл (IO-3)
            try:
                with open(output_file, 'w') as f:
                    f.write(output_line)
            except Exception as e:
                print(f"Ошибка записи в файл {output_file}: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Вывод в stdout
            sys.stdout.write(output_line)


def main():
    parser = argparse.ArgumentParser(
        description='Утилита для шифрования/расшифрования данных и вычисления хеш-сумм',
        prog='cryptocore'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')
    
    # Парсер для команды шифрования/дешифрования
    crypto_parser = subparsers.add_parser('encrypt', help='Шифрование файла')
    crypto_parser.add_argument('--decrypt', action='store_true', help='Выполнить дешифрование (по умолчанию - шифрование)')
    crypto_parser.add_argument('--algorithm', required=True, choices=['aes'],
                              help='Алгоритм шифрования (только aes)')
    crypto_parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                              help='Режим работы')
    crypto_parser.add_argument('--key', required=False,
                              help='Ключ в виде шестнадцатеричной строки (16 байт)')
    crypto_parser.add_argument('--input', required=True,
                              help='Путь к входному файлу')
    crypto_parser.add_argument('--output',
                              help='Путь к выходному файлу (опционально)')
    crypto_parser.add_argument('--iv',
                              help='Вектор инициализации в виде шестнадцатеричной строки (только для дешифрования)')
    crypto_parser.add_argument('-v', '--verbose', action='store_true',
                              help='Подробный вывод')
    
    # Парсер для команды хеширования (CLI-1) с поддержкой HMAC
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
        # Обработка команды хеширования/HMAC
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
        # Проверка использования IV для старого интерфейса
        if args.decrypt and args.mode == 'ecb' and args.iv:
            print("Предупреждение: IV указан для режима ECB и будет проигнорирован", file=sys.stderr)
        
        # Определение операции
        operation = 'decrypt' if args.decrypt else 'encrypt'
        
        # Генерация имени выходного файла если не указан
        if not args.output:
            if operation == 'encrypt':
                args.output = args.input + '.enc'
            else:
                args.output = args.input + '.dec'
            if args.verbose:
                print(f"Выходной файл не указан, используется: {args.output}")
        
        # Создание экземпляра и обработка
        crypto = CryptoCore(verbose=args.verbose)
        crypto.process_file(
            algorithm=args.algorithm,
            mode=args.mode,
            operation=operation,
            key_hex=args.key,
            input_file=args.input,
            output_file=args.output,
            iv_hex=args.iv if args.decrypt else None
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
