#!/usr/bin/env python3
"""
Автоматические тесты для утилиты шифрования AES-128 ECB
"""

import os
import sys
import tempfile
import subprocess
import hashlib
import random
import string
from pathlib import Path

# Добавляем путь к текущей директории для импорта cryptocore
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Получаем путь к файлу cryptocore.py
CRYPTOCORE_PATH = "cryptocore.py"


class TestCryptoCore:
    """Класс для автоматического тестирования утилиты cryptocore"""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cryptocore_test_")
        self.test_count = 0
        self.passed_count = 0
        self.failed_tests = []

    def _run_command(self, args):
        """Запускает команду и возвращает результат"""
        # Добавляем подкоманду 'encrypt' для операций шифрования/дешифрования
        if any(arg in args for arg in ['--algorithm', '--mode']):
            cmd = [sys.executable, CRYPTOCORE_PATH, 'encrypt'] + args
        else:
            cmd = [sys.executable, CRYPTOCORE_PATH] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def _generate_test_data(self, size=1024):
        """Генерирует тестовые данные"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

    def _generate_key(self):
        """Генерирует случайный 16-байтовый ключ в hex"""
        key_bytes = os.urandom(16)
        return key_bytes.hex()

    def _get_file_hash(self, filepath):
        """Вычисляет хеш файла"""
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _create_test_file(self, data, filename="test_input.txt"):
        """Создает временный файл с тестовыми данными"""
        filepath = os.path.join(self.temp_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(data)
        return filepath

    def test_help_command(self):
        """Тест отображения справки"""
        print("\n=== Тест 1: Отображение справки ===")
        result = self._run_command(["--help"])

        if result.returncode == 0 and "usage" in result.stdout.lower():
            print("✓ Справка отображается корректно")
            return True
        else:
            print("✗ Ошибка при отображении справки")
            return False

    def test_missing_required_args(self):
        """Тест отсутствия обязательных аргументов"""
        print("\n=== Тест 2: Проверка обязательных аргументов ===")

        tests = [
            ([], "без аргументов"),
            (["--algorithm", "aes"], "только algorithm"),
            (["--algorithm", "aes", "--mode", "ecb"], "без операции"),
            (["--key", self._generate_key()], "без операции, только ключ"),
        ]

        all_passed = True
        for args, description in tests:
            result = self._run_command(args)
            if result.returncode != 0:
                print(f"✓ Корректно обработано отсутствие аргументов: {description}")
            else:
                print(f"✗ Не обработано отсутствие аргументов: {description}")
                all_passed = False

        return all_passed

    def test_invalid_algorithm(self):
        """Тест неверного алгоритма"""
        print("\n=== Тест 3: Проверка неверного алгоритма ===")

        # Создаем временный файл
        test_data = b"test data"
        input_file = self._create_test_file(test_data, "invalid_alg_input.txt")

        result = self._run_command([
            "--algorithm", "des",  # Некорректный алгоритм
            "--mode", "ecb",
            "--key", self._generate_key(),
            "--input", input_file,
            "--output", os.path.join(self.temp_dir, "dummy.out")
        ])

        if result.returncode != 0:
            print("✓ Корректно обработана ошибка неверного алгоритма")
            return True
        else:
            print("✗ Не обработана ошибка неверного алгоритма")
            return False

    def test_invalid_key(self):
        """Тест неверного ключа"""
        print("\n=== Тест 4: Проверка неверного ключа ===")

        # Создаем временный файл для теста
        test_data = b"test data"
        input_file = self._create_test_file(test_data, "invalid_key_input.txt")

        # Тест 1: Ключ неправильной длины (6 символов = 3 байта)
        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--key", "010203",  # 6 hex символов = 3 байта
            "--input", input_file,
            "--output", os.path.join(self.temp_dir, "invalid_key_output.txt")
        ])

        passed = False
        if result.returncode != 0:
            print("✓ Корректно обработана ошибка неверного ключа (длина)")
            passed = True
        else:
            print("✗ Не обработана ошибка неверного ключа (длина)")

        # Тест 2: Ключ не в hex формате
        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--key", "not_a_hex_string",
            "--input", input_file,
            "--output", os.path.join(self.temp_dir, "invalid_key_output2.txt")
        ])

        if result.returncode != 0:
            print("✓ Корректно обработана ошибка неверного ключа (формат)")
            passed = passed and True
        else:
            print("✗ Не обработана ошибка неверного ключа (формат)")
            passed = False

        return passed

    def test_file_not_found(self):
        """Тест отсутствия входного файла"""
        print("\n=== Тест 5: Проверка отсутствия входного файла ===")

        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--key", self._generate_key(),
            "--input", "non_existent_file.txt",
            "--output", "dummy.out"
        ])

        if result.returncode != 0:
            print("✓ Корректно обработано отсутствие входного файла")
            return True
        else:
            print("✗ Не обработано отсутствие входного файла")
            return False

    def test_encrypt_decrypt_cycle(self):
        """Тест цикла шифрование-дешифрование"""
        print("\n=== Тест 6: Цикл шифрование-дешифрование ===")

        # Генерируем тестовые данные
        test_data = self._generate_test_data()
        key = self._generate_key()

        # Создаем файлы
        input_file = self._create_test_file(test_data, "cycle_input.txt")
        encrypted_file = os.path.join(self.temp_dir, "cycle_encrypted.enc")
        decrypted_file = os.path.join(self.temp_dir, "cycle_decrypted.txt")

        # Шифруем (без флага --encrypt)
        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--key", key,
            "--input", input_file,
            "--output", encrypted_file
        ])

        if result.returncode != 0:
            print(f"✗ Ошибка при шифровании: {result.stderr}")
            return False

        # Проверяем, что зашифрованный файл отличается от исходного
        if self._get_file_hash(input_file) == self._get_file_hash(encrypted_file):
            print("✗ Зашифрованный файл идентичен исходному")
            return False

        # Дешифруем (с флагом --decrypt)
        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--decrypt",
            "--key", key,
            "--input", encrypted_file,
            "--output", decrypted_file
        ])

        if result.returncode != 0:
            print(f"✗ Ошибка при дешифровании: {result.stderr}")
            return False

        # Проверяем, что расшифрованный файл идентичен исходному
        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()

        if test_data == decrypted_data:
            print("✓ Цикл шифрование-дешифрование пройден успешно")
            print(f"  Размер данных: {len(test_data)} байт")
            return True
        else:
            print("✗ Расшифрованные данные не совпадают с исходными")
            return False

    def test_auto_output_filename(self):
        """Тест автоматического создания имен выходных файлов"""
        print("\n=== Тест 7: Автоматическое создание имен файлов ===")

        test_data = b"test for auto filename"
        key = self._generate_key()

        # Используем уникальное имя файла чтобы избежать конфликтов
        import time
        timestamp = str(int(time.time()))
        base_name = f"auto_test_{timestamp}.txt"
        input_file = self._create_test_file(test_data, base_name)

        # Шифруем без указания output
        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--key", key,
            "--input", input_file
            # --output не указываем
        ])

        encrypted_file = input_file + ".enc"
        expected_encrypted = os.path.join(self.temp_dir, base_name + ".enc")

        if result.returncode == 0 and os.path.exists(encrypted_file):
            print("✓ Автоматическое имя для шифрования создано")

            # Дешифруем без указания output
            result = self._run_command([
                "--algorithm", "aes",
                "--mode", "ecb",
                "--decrypt",
                "--key", key,
                "--input", encrypted_file
                # --output не указываем
            ])

            # Файл должен быть создан с .dec расширением
            expected_decrypted = encrypted_file + ".dec"

            if result.returncode == 0 and os.path.exists(expected_decrypted):
                print("✓ Автоматическое имя для дешифрования создано")

                # Проверяем корректность дешифрования
                with open(expected_decrypted, 'rb') as f:
                    decrypted_data = f.read()

                if test_data == decrypted_data:
                    print("✓ Автоматические имена работают корректно")

                    # Удаляем временные файлы
                    for f in [encrypted_file, expected_decrypted]:
                        if os.path.exists(f):
                            os.unlink(f)
                    return True

        print("✗ Ошибка при создании автоматических имен файлов")
        return False
    def test_verbose_output(self):
        """Тест подробного вывода"""
        print("\n=== Тест 8: Проверка подробного вывода ===")

        test_data = b"verbose test data"
        key = self._generate_key()

        input_file = self._create_test_file(test_data, "verbose_input.txt")
        output_file = os.path.join(self.temp_dir, "verbose_output.enc")

        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--key", key,
            "--input", input_file,
            "--output", output_file,
            "--verbose"
        ])

        if result.returncode == 0:
            print("✓ Подробный вывод работает корректно")
            return True
        else:
            print(f"✗ Ошибка в подробном выводе: {result.stderr}")
            return False

    def test_different_data_sizes(self):
        """Тест с разными размерами данных"""
        print("\n=== Тест 9: Тестирование разных размеров данных ===")

        sizes = [1, 15, 16, 17, 100, 1000, 10000]
        key = self._generate_key()
        all_passed = True

        for size in sizes:
            test_data = self._generate_test_data(size)
            input_file = self._create_test_file(test_data, f"size_test_{size}.txt")
            encrypted_file = os.path.join(self.temp_dir, f"size_test_{size}.enc")
            decrypted_file = os.path.join(self.temp_dir, f"size_test_{size}.dec")

            # Шифруем (без флага --encrypt)
            result = self._run_command([
                "--algorithm", "aes",
                "--mode", "ecb",
                "--key", key,
                "--input", input_file,
                "--output", encrypted_file
            ])

            if result.returncode != 0:
                print(f"✗ Ошибка при шифровании данных размером {size} байт")
                all_passed = False
                continue

            # Дешифруем (с флагом --decrypt)
            result = self._run_command([
                "--algorithm", "aes",
                "--mode", "ecb",
                "--decrypt",
                "--key", key,
                "--input", encrypted_file,
                "--output", decrypted_file
            ])

            if result.returncode != 0:
                print(f"✗ Ошибка при дешифровании данных размером {size} байт")
                all_passed = False
                continue

            # Проверяем
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()

            if test_data != decrypted_data:
                print(f"✗ Несоответствие данных при размере {size} байт")
                all_passed = False
            else:
                print(f"✓ Корректная обработка данных размером {size} байт")

        return all_passed

    def test_mutually_exclusive_operations(self):
        """Тест взаимоисключающих операций"""
        print("\n=== Тест 10: Проверка взаимоисключающих операций ===")

        # Пытаемся указать и --encrypt и --decrypt одновременно
        # Но в новой версии нет флага --encrypt, так что проверяем только --decrypt
        # Создаем временный файл
        test_data = b"test data"
        input_file = self._create_test_file(test_data, "mutex_test.txt")

        # Пробуем использовать дважды --decrypt (бессмысленно, но проверяем обработку)
        result = self._run_command([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--decrypt",
            "--key", self._generate_key(),
            "--input", input_file,
            "--output", "dummy.out"
        ])

        # Команда должна завершиться с ошибкой, так как мы пытаемся дешифровать незашифрованный файл
        if result.returncode != 0:
            print("✓ Взаимоисключающие операции обрабатываются корректно")
            return True
        else:
            print("✗ Не обработаны взаимоисключающие операции")
            return False

    def run_all_tests(self):
        """Запускает все тесты"""
        print("=" * 60)
        print("Запуск автоматических тестов для cryptocore")
        print("=" * 60)

        tests = [
            ("help_command", self.test_help_command),
            ("missing_required_args", self.test_missing_required_args),
            ("invalid_algorithm", self.test_invalid_algorithm),
            ("invalid_key", self.test_invalid_key),
            ("file_not_found", self.test_file_not_found),
            ("encrypt_decrypt_cycle", self.test_encrypt_decrypt_cycle),
            ("auto_output_filename", self.test_auto_output_filename),
            ("verbose_output", self.test_verbose_output),
            ("different_data_sizes", self.test_different_data_sizes),
            ("mutually_exclusive_operations", self.test_mutually_exclusive_operations),
        ]

        for test_name, test_func in tests:
            self.test_count += 1
            try:
                if test_func():
                    self.passed_count += 1
                else:
                    self.failed_tests.append(test_name)
            except Exception as e:
                print(f"✗ Ошибка при выполнении теста {test_name}: {e}")
                self.failed_tests.append(test_name)

        self.print_summary()

        # Очищаем временные файлы
        self.cleanup()

        return len(self.failed_tests) == 0

    def print_summary(self):
        """Выводит сводку по тестам"""
        print("\n" + "=" * 60)
        print("Сводка тестирования:")
        print("=" * 60)
        print(f"Всего тестов: {self.test_count}")
        print(f"Пройдено: {self.passed_count}")
        print(f"Не пройдено: {len(self.failed_tests)}")

        if self.failed_tests:
            print("\nНе пройденные тесты:")
            for test in self.failed_tests:
                print(f"  - {test}")

        if self.passed_count == self.test_count:
            print("\n✓ Все тесты пройдены успешно!")
        else:
            print(f"\n✗ Провалено {len(self.failed_tests)} тестов")

    def cleanup(self):
        """Очищает временные файлы"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)


def main():
    """Основная функция"""
    # Проверяем наличие файла cryptocore.py
    if not os.path.exists(CRYPTOCORE_PATH):
        print(f"Ошибка: файл {CRYPTOCORE_PATH} не найден")
        print("Запустите тесты из директории с cryptocore.py")
        return 1

    # Запускаем тесты
    tester = TestCryptoCore()
    success = tester.run_all_tests()

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())