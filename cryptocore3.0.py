
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Импорт нашего CSPRNG модуля
try:
    from csprng import generate_random_bytes
except ImportError:
    # Для обратной совместимости в случае, если модуль еще не создан
    import os


    def generate_random_bytes(num_bytes: int) -> bytes:
        return os.urandom(num_bytes)


class CryptoCore:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.block_size = AES.block_size  # 16 bytes for AES

    def _validate_key(self, key_hex: str) -> bytes:
        """Проверка и преобразование ключа из hex строки"""
        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 16:
                raise ValueError("Ключ должен быть 16 байт для AES-128")
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


def main():
    parser = argparse.ArgumentParser(
        description='Утилита для шифрования и расшифрования данных AES-128',
        prog='cryptocore'
    )

    # Обязательные аргументы
    parser.add_argument('--algorithm', required=True, choices=['aes'],
                        help='Алгоритм шифрования (только aes)')
    parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Режим работы')

    # Взаимоисключающие флаги для операции
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt', action='store_true',
                                 help='Выполнить шифрование')
    operation_group.add_argument('--decrypt', action='store_true',
                                 help='Выполнить дешифрование')

    # Ключ теперь опционален для шифрования (CLI-1)
    parser.add_argument('--key', required=False,
                        help='Ключ в виде шестнадцатеричной строки (16 байт)')

    parser.add_argument('--input', required=True,
                        help='Путь к входному файлу')
    parser.add_argument('--output',
                        help='Путь к выходному файлу (опционально)')
    parser.add_argument('--iv',
                        help='Вектор инициализации в виде шестнадцатеричной строки (только для дешифрования)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Подробный вывод')

    args = parser.parse_args()

    # Проверка использования IV (CLI-3 из Спринта 2)
    if args.encrypt and args.iv:
        print("Предупреждение: IV указан при шифровании и будет проигнорирован", file=sys.stderr)

    if args.decrypt and args.mode == 'ecb' and args.iv:
        print("Предупреждение: IV указан для режима ECB и будет проигнорирован", file=sys.stderr)

    # Определение операции
    operation = 'encrypt' if args.encrypt else 'decrypt'

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


if __name__ == '__main__':
    main()