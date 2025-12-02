import os
import sys
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class CryptoCore:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

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

    def process_file(self, algorithm: str, mode: str, operation: str,
                     key_hex: str, input_file: str, output_file: str):
        """Основной метод обработки файла"""

        # Валидация аргументов
        if algorithm != 'aes':
            print("Ошибка: поддерживается только алгоритм 'aes'", file=sys.stderr)
            sys.exit(1)

        if mode != 'ecb':
            print("Ошибка: поддерживается только режим 'ecb'", file=sys.stderr)
            sys.exit(1)

        # Преобразование ключа
        key = self._validate_key(key_hex)

        # Чтение входных данных
        input_data = self._read_file(input_file)

        # Определение операции
        is_encrypt = (operation == 'encrypt')

        # Обработка данных
        try:
            output_data = self._process_ecb(input_data, key, is_encrypt)
        except Exception as e:
            print(f"Ошибка при обработке данных: {e}", file=sys.stderr)
            sys.exit(1)

        # Запись результата
        self._write_file(output_file, output_data)

        if self.verbose:
            op_name = "шифрования" if is_encrypt else "дешифрования"
            print(f"Операция {op_name} успешно завершена")
            print(f"Входной файл: {input_file}")
            print(f"Выходной файл: {output_file}")
            print(f"Размер обработанных данных: {len(output_data)} байт")


def main():
    parser = argparse.ArgumentParser(
        description='Утилита для шифрования и расшифрования данных AES-128 ECB',
        prog='cryptocore'
    )

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
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Подробный вывод')

    args = parser.parse_args()

    # Определение операции
    operation = 'encrypt' if args.encrypt else 'decrypt'

    # Генерация имени выходного файла если не указан (CLI-5)
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
        output_file=args.output
    )


if __name__ == '__main__':
    main()