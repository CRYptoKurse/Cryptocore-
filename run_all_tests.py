#!/usr/bin/env python3
"""
Главный скрипт для запуска всех тестов CryptoCore с исправленными командами
Запуск: python run_all_tests_fixed.py
"""

import os
import sys
import subprocess
import argparse
import traceback
from pathlib import Path


def run_test(test_name, test_file, args=None):
    """Запускает один тестовый скрипт"""
    print(f"\n{'=' * 80}")
    print(f"ЗАПУСК ТЕСТА: {test_name}")
    print(f"{'=' * 80}")

    if not os.path.exists(test_file):
        print(f"Файл теста не найден: {test_file}")
        return False

    try:
        cmd = [sys.executable, test_file]
        if args:
            cmd.extend(args)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=300  # 5 минут таймаут
        )

        print(f"Код возврата: {result.returncode}")

        if result.stdout:
            print("\nSTDOUT:")
            print(result.stdout[:5000])  # Ограничиваем вывод

        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr[:2000])  # Ограничиваем вывод

        if result.returncode == 0:
            print(f"\n✓ ТЕСТ '{test_name}' УСПЕШНО ПРОЙДЕН")
            return True
        else:
            print(f"\n✗ ТЕСТ '{test_name}' НЕ ПРОЙДЕН")
            return False

    except subprocess.TimeoutExpired:
        print(f"\n✗ ТЕСТ '{test_name}' ПРЕВЫСИЛ ЛИМИТ ВРЕМЕНИ (5 минут)")
        return False
    except Exception as e:
        print(f"\n✗ ОШИБКА ПРИ ЗАПУСКЕ ТЕСТА '{test_name}': {e}")
        traceback.print_exc()
        return False


def check_environment():
    """Проверяет окружение и наличие необходимых файлов"""
    print("Проверка окружения...")

    # Проверяем наличие cryptocore.py или Core.py
    cryptocore_files = ['cryptocore.py', 'Core.py']
    found = False
    for file in cryptocore_files:
        if os.path.exists(file):
            print(f"Найден файл: {file}")
            found = True

    if not found:
        print("ВНИМАНИЕ: Файл cryptocore.py или Core.py не найден в текущей директории")
        print("Тесты могут завершиться с ошибкой")
        return False

    # Проверяем Python версию
    python_version = sys.version_info
    print(f"Python версия: {python_version.major}.{python_version.minor}.{python_version.micro}")

    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 7):
        print("ВНИМАНИЕ: Требуется Python 3.7 или выше")

    # Проверяем наличие необходимых модулей
    required_modules = ['Crypto', 'hashlib']
    for module in required_modules:
        try:
            __import__(module)
            print(f"Модуль {module}: OK")
        except ImportError:
            print(f"ВНИМАНИЕ: Модуль {module} не найден")

    return True


def get_test_suite(use_fixed=True):
    """Возвращает список всех тестов (исправленных или оригинальных)"""
    if use_fixed:
        return {
            'sprint1': {
                'name': 'Спринт 1 - AES-128 ECB (исправленный)',
                'file': 'spr1_fixed.py' if os.path.exists('spr1_fixed.py') else 'spr1.py',
                'description': 'Тестирование базового шифрования AES-128 в режиме ECB'
            },
            'sprint2': {
                'name': 'Спринт 2 - Режимы шифрования (исправленный)',
                'file': 'spr2_fixed.py' if os.path.exists('spr2_fixed.py') else 'spr2.py',
                'description': 'Тестирование режимов CBC, CFB, OFB, CTR'
            },
            'sprint4': {
                'name': 'Спринт 4 - Хеш-функции (исправленный)',
                'file': 'spr4_fixed.py' if os.path.exists('spr4_fixed.py') else 'spr4.py',
                'description': 'Тестирование SHA-256 и SHA3-256'
            },
            'hmac': {
                'name': 'HMAC',
                'file': 'test_hmac.py',
                'description': 'Тестирование HMAC (Спринт 5)'
            },
            'pbkdf2': {
                'name': 'PBKDF2 и HKDF',
                'file': 'test_pbkdf2.py',
                'description': 'Тестирование PBKDF2 и HKDF (Спринт 5)'
            },
            'gcm': {
                'name': 'GCM',
                'file': 'test_gcm.py',
                'description': 'Тестирование режима GCM (Спринт 6)'
            },
            'etm': {
                'name': 'Encrypt-then-MAC',
                'file': 'test_etmv.py',
                'description': 'Тестирование Encrypt-then-MAC (Спринт 6)'
            },
            'sprint6': {
                'name': 'Спринт 6 - Комплексные тесты ETM (исправленный)',
                'file': 'spr6_fixed.py' if os.path.exists('spr6_fixed.py') else 'spr6.py',
                'description': 'Комплексные тесты для Encrypt-then-MAC'
            }
        }
    else:
        # Оригинальные тесты
        return {
            'sprint1': {'name': 'Спринт 1 - AES-128 ECB', 'file': 'spr1.py',
                        'description': 'Тестирование базового шифрования AES-128 в режиме ECB'},
            'sprint2': {'name': 'Спринт 2 - Режимы шифрования', 'file': 'spr2.py',
                        'description': 'Тестирование режимов CBC, CFB, OFB, CTR'},
            'sprint4': {'name': 'Спринт 4 - Хеш-функции', 'file': 'spr4.py',
                        'description': 'Тестирование SHA-256 и SHA3-256'},
            'hmac': {'name': 'HMAC', 'file': 'test_hmac.py', 'description': 'Тестирование HMAC (Спринт 5)'},
            'pbkdf2': {'name': 'PBKDF2 и HKDF', 'file': 'test_pbkdf2.py',
                       'description': 'Тестирование PBKDF2 и HKDF (Спринт 5)'},
            'gcm': {'name': 'GCM', 'file': 'test_gcm.py', 'description': 'Тестирование режима GCM (Спринт 6)'},
            'etm': {'name': 'Encrypt-then-MAC', 'file': 'test_etmv.py',
                    'description': 'Тестирование Encrypt-then-MAC (Спринт 6)'},
            'sprint6': {'name': 'Спринт 6 - Комплексные тесты ETM', 'file': 'spr6.py',
                        'description': 'Комплексные тесты для Encrypt-then-MAC'}
        }


def main():
    """Основная функция запуска всех тестов"""
    parser = argparse.ArgumentParser(description='Запуск всех тестов CryptoCore с исправленными командами')
    parser.add_argument('--test', help='Запустить конкретный тест по имени')
    parser.add_argument('--list', action='store_true', help='Показать список тестов')
    parser.add_argument('--no-fixed', action='store_true', help='Использовать оригинальные тесты (без исправлений)')
    args = parser.parse_args()

    if args.list:
        tests = get_test_suite(use_fixed=not args.no_fixed)
        print("Доступные тесты:")
        for key, test in tests.items():
            print(f"  {key}: {test['name']}")
            print(f"     Файл: {test['file']}")
            print(f"     Описание: {test['description']}")
            print()
        return

    print("=" * 80)
    print("ЗАПУСК ВСЕХ ТЕСТОВ CRYPTOCORE (ИСПРАВЛЕННЫЕ КОМАНДЫ)")
    print("=" * 80)

    # Проверяем окружение
    if not check_environment():
        print("\nПродолжить несмотря на предупреждения? (y/n): ", end='')
        if input().lower() != 'y':
            return 1

    # Получаем список тестов
    tests = get_test_suite(use_fixed=not args.no_fixed)

    # Фильтруем по конкретному тесту если указано
    if args.test:
        if args.test in tests:
            tests = {args.test: tests[args.test]}
        else:
            print(f"\nОШИБКА: Тест '{args.test}' не найден")
            return 1

    # Запускаем тесты
    print(f"\nБудет запущено тестов: {len(tests)}")
    print("=" * 80)

    results = {}
    for i, (key, test_info) in enumerate(tests.items(), 1):
        print(f"\n[{i}/{len(tests)}] Подготовка к запуску: {test_info['name']}")

        success = run_test(test_info['name'], test_info['file'])
        results[key] = success

        if not success:
            print("\nПродолжить выполнение остальных тестов? (y/n): ", end='')
            if input().lower() != 'y':
                break

    # Выводим итоговый отчет
    print("\n" + "=" * 80)
    print("ИТОГОВЫЙ ОТЧЕТ")
    print("=" * 80)

    total = len(results)
    passed = sum(1 for success in results.values() if success)
    failed = total - passed

    print(f"Всего тестов: {total}")
    print(f"Пройдено: {passed}")
    print(f"Не пройдено: {failed}")

    if failed > 0:
        print("\nНе пройденные тесты:")
        for key, success in results.items():
            if not success:
                print(f"  ✗ {tests[key]['name']}")

    print("\n" + "=" * 80)
    if failed == 0:
        print("🎉 ВСЕ ТЕСТЫ УСПЕШНО ПРОЙДЕНЫ!")
        return 0
    else:
        print(f"⚠️  Некоторые тесты не пройдены ({failed} из {total})")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nЗапуск тестов прерыван пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        traceback.print_exc()
        sys.exit(1)