#!/usr/bin/env python3
"""
Тестовый скрипт для проверки функций хеширования CryptoCore (Спринт 4)
Запуск: python test_hash.py
"""

import os
import subprocess
import tempfile
import hashlib
import time
import random
import sys

def run_command(cmd):
    """Запуск команды и получение результата"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        print(f"Ошибка выполнения команды: {e}")
        return -1, "", ""

def create_test_file(filename, content=None, size_mb=10):
    """Создание тестового файла"""
    if content is not None:
        with open(filename, 'wb') as f:
            f.write(content)
    else:
        # Создаем большой файл со случайными данными
        chunk_size = 1024 * 1024  # 1 MB
        with open(filename, 'wb') as f:
            for _ in range(size_mb):
                f.write(os.urandom(chunk_size))
    return filename

def test_empty_file():
    """TEST-2: Хеширование пустого файла"""
    print("\n" + "="*60)
    print("TEST-2: Хеширование пустого файла")
    print("="*60)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b'')
        empty_file = f.name
    
    # Тестовые векторы для пустых файлов
    expected_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    expected_sha3_256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    
    # Тест SHA-256
    cmd = f"python cryptocore.py dgst --algorithm sha256 --input {empty_file}"
    ret, out, err = run_command(cmd)
    
    if ret == 0:
        hash_value = out.split()[0]
        if hash_value == expected_sha256:
            print(f"✓ SHA-256 пустого файла: {hash_value}")
            print("  Результат CORRECT!")
        else:
            print(f"✗ SHA-256 пустого файла: {hash_value}")
            print(f"  Ожидалось: {expected_sha256}")
            print("  Результат INCORRECT!")
    else:
        print(f"✗ Ошибка выполнения команды: {err}")
    
    # Тест SHA3-256
    cmd = f"python cryptocore.py dgst --algorithm sha3-256 --input {empty_file}"
    ret, out, err = run_command(cmd)
    
    if ret == 0:
        hash_value = out.split()[0]
        if hash_value == expected_sha3_256:
            print(f"✓ SHA3-256 пустого файла: {hash_value}")
            print("  Результат CORRECT!")
        else:
            print(f"✗ SHA3-256 пустого файла: {hash_value}")
            print(f"  Ожидалось: {expected_sha3_256}")
            print("  Результат INCORRECT!")
    else:
        print(f"✗ Ошибка выполнения команды: {err}")
    
    os.unlink(empty_file)
    return ret == 0

def test_nist_vectors():
    """TEST-1: Тесты с известными векторами NIST"""
    print("\n" + "="*60)
    print("TEST-1: Тестовые векторы NIST")
    print("="*60)
    
    # Тестовые векторы из NIST
    test_cases = [
        # (сообщение, sha256, sha3_256)
        (b"abc", 
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
         "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
        
        (b"",  # уже тестировали, но включим для полноты
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ]
    
    passed = 0
    total = 0
    
    for i, (message, expected_sha256, expected_sha3) in enumerate(test_cases):
        total += 2  # по одному тесту на каждый алгоритм
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(message)
            test_file = f.name
        
        # Тест SHA-256
        cmd = f"python cryptocore.py dgst --algorithm sha256 --input {test_file}"
        ret, out, err = run_command(cmd)
        
        if ret == 0:
            hash_value = out.split()[0]
            if hash_value == expected_sha256:
                print(f"✓ Тест {i+1}.1 SHA-256: CORRECT")
                passed += 1
            else:
                print(f"✗ Тест {i+1}.1 SHA-256: INCORRECT")
                print(f"  Получено: {hash_value}")
                print(f"  Ожидалось: {expected_sha256}")
        else:
            print(f"✗ Тест {i+1}.1 SHA-256: Ошибка - {err}")
        
        # Тест SHA3-256
        cmd = f"python cryptocore.py dgst --algorithm sha3-256 --input {test_file}"
        ret, out, err = run_command(cmd)
        
        if ret == 0:
            hash_value = out.split()[0]
            if hash_value == expected_sha3:
                print(f"✓ Тест {i+1}.2 SHA3-256: CORRECT")
                passed += 1
            else:
                print(f"✗ Тест {i+1}.2 SHA3-256: INCORRECT")
                print(f"  Получено: {hash_value}")
                print(f"  Ожидалось: {expected_sha3}")
        else:
            print(f"✗ Тест {i+1}.2 SHA3-256: Ошибка - {err}")
        
        os.unlink(test_file)
    
    print(f"\nРезультат: {passed}/{total} тестов пройдено")
    return passed == total

def test_compatibility():
    """TEST-3: Совместимость с системными утилитами"""
    print("\n" + "="*60)
    print("TEST-3: Совместимость с системными утилитами")
    print("="*60)
    
    # Создаем тестовый файл
    test_data = b"Hello, CryptoCore! This is a test file for hash compatibility."
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(test_data)
        test_file = f.name
    
    passed = 0
    total = 0
    
    # Проверяем доступность системных утилит
    sha256sum_available = False
    sha3sum_available = False
    
    # Проверка sha256sum
    ret, _, _ = run_command("which sha256sum")
    if ret == 0:
        sha256sum_available = True
        total += 1
    
    # Проверка sha3sum
    ret, _, _ = run_command("which sha3sum")
    if ret == 0:
        sha3sum_available = True
        total += 1
    
    if sha256sum_available:
        # Получаем хеш через sha256sum
        cmd = f"sha256sum {test_file}"
        ret, out, err = run_command(cmd)
        if ret == 0:
            system_hash = out.split()[0]
            
            # Получаем хеш через нашу утилиту
            cmd = f"python cryptocore.py dgst --algorithm sha256 --input {test_file}"
            ret, out, err = run_command(cmd)
            if ret == 0:
                our_hash = out.split()[0]
                
                if system_hash == our_hash:
                    print(f"✓ SHA-256 совместимость: CORRECT")
                    print(f"  Наш хеш:     {our_hash}")
                    print(f"  Системный:   {system_hash}")
                    passed += 1
                else:
                    print(f"✗ SHA-256 совместимость: INCORRECT")
                    print(f"  Наш хеш:     {our_hash}")
                    print(f"  Системный:   {system_hash}")
            else:
                print(f"✗ Ошибка нашей утилиты: {err}")
        else:
            print("✗ Не удалось получить хеш через sha256sum")
    
    if sha3sum_available:
        # Получаем хеш через sha3sum
        cmd = f"sha3sum -a 256 {test_file}"
        ret, out, err = run_command(cmd)
        if ret == 0:
            system_hash = out.split()[0]
            
            # Получаем хеш через нашу утилиту
            cmd = f"python cryptocore.py dgst --algorithm sha3-256 --input {test_file}"
            ret, out, err = run_command(cmd)
            if ret == 0:
                our_hash = out.split()[0]
                
                if system_hash == our_hash:
                    print(f"✓ SHA3-256 совместимость: CORRECT")
                    print(f"  Наш хеш:     {our_hash}")
                    print(f"  Системный:   {system_hash}")
                    passed += 1
                else:
                    print(f"✗ SHA3-256 совместимость: INCORRECT")
                    print(f"  Наш хеш:     {our_hash}")
                    print(f"  Системный:   {system_hash}")
            else:
                print(f"✗ Ошибка нашей утилиты: {err}")
        else:
            print("✗ Не удалось получить хеш через sha3sum")
    
    if total == 0:
        print("⚠ Системные утилиты не найдены, тест пропущен")
        print("  Установите: sudo apt-get install coreutils sha3sum")
        return True  # Пропускаем тест
    
    os.unlink(test_file)
    print(f"\nРезультат: {passed}/{total} тестов совместимости пройдено")
    return passed == total

def test_large_file():
    """TEST-4: Хеширование большого файла"""
    print("\n" + "="*60)
    print("TEST-4: Хеширование большого файла (10 MB)")
    print("="*60)
    
    # Создаем большой файл (10 MB для быстрого тестирования)
    large_file = "large_test_file.bin"
    size_mb = 10
    
    print(f"Создание файла {size_mb} MB...")
    create_test_file(large_file, size_mb=size_mb)
    file_size = os.path.getsize(large_file)
    print(f"Создан файл: {large_file} ({file_size / (1024*1024):.2f} MB)")
    
    # Хешируем с помощью нашей утилиты
    start_time = time.time()
    
    cmd = f"python cryptocore.py dgst --algorithm sha256 --input {large_file}"
    ret, out, err = run_command(cmd)
    
    elapsed = time.time() - start_time
    
    if ret == 0:
        our_hash = out.split()[0]
        print(f"✓ Хеш SHA-256 большого файла: {our_hash}")
        print(f"  Время выполнения: {elapsed:.2f} секунд")
        print(f"  Скорость: {file_size / elapsed / (1024*1024):.2f} MB/сек")
        
        # Проверяем с помощью hashlib
        print("\nПроверка с помощью Python hashlib...")
        start_time = time.time()
        sha256 = hashlib.sha256()
        with open(large_file, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        expected_hash = sha256.hexdigest()
        lib_elapsed = time.time() - start_time
        
        if our_hash == expected_hash:
            print(f"✓ Хеши совпадают!")
            print(f"  Время hashlib: {lib_elapsed:.2f} секунд")
            result = True
        else:
            print(f"✗ Хеши не совпадают!")
            print(f"  Наш: {our_hash}")
            print(f"  Ожидаемый: {expected_hash}")
            result = False
    else:
        print(f"✗ Ошибка: {err}")
        result = False
    
    # Очистка
    os.unlink(large_file)
    return result

def test_avalanche_effect():
    """TEST-5: Лавинный эффект"""
    print("\n" + "="*60)
    print("TEST-5: Лавинный эффект")
    print("="*60)
    
    # Создаем два файла с разницей в один бит
    data1 = bytearray(os.urandom(1024))  # 1KB случайных данных
    data2 = data1.copy()
    
    # Меняем один бит в середине
    byte_index = len(data1) // 2
    bit_index = 3
    data2[byte_index] ^= (1 << bit_index)  # Инвертируем один бит
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f1:
        f1.write(data1)
        file1 = f1.name
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f2:
        f2.write(data2)
        file2 = f2.name
    
    print(f"Созданы 2 файла с разницей в ОДНОМ бите")
    print(f"  Файл 1: {file1}")
    print(f"  Файл 2: {file2}")
    
    # Получаем хеши через нашу утилиту
    cmd = f"python cryptocore.py dgst --algorithm sha256 --input {file1}"
    ret, out1, err = run_command(cmd)
    if ret != 0:
        print(f"✗ Ошибка для файла 1: {err}")
        return False
    
    cmd = f"python cryptocore.py dgst --algorithm sha256 --input {file2}"
    ret, out2, err = run_command(cmd)
    if ret != 0:
        print(f"✗ Ошибка для файла 2: {err}")
        return False
    
    hash1 = out1.split()[0]
    hash2 = out2.split()[0]
    
    print(f"\nХеш файла 1: {hash1}")
    print(f"Хеш файла 2: {hash2}")
    
    # Сравниваем хеши
    if hash1 == hash2:
        print("✗ Хеши совпадают! Лавинный эффект не работает!")
        result = False
    else:
        # Подсчитываем различающиеся биты
        hex1 = int(hash1, 16)
        hex2 = int(hash2, 16)
        
        # XOR покажет различающиеся биты
        xor_result = hex1 ^ hex2
        
        # Подсчет установленных битов (Hamming weight)
        diff_bits = bin(xor_result).count('1')
        
        print(f"\nРазличающиеся биты: {diff_bits}/256 ({diff_bits/256*100:.1f}%)")
        
        # Для хорошего лавинного эффекта должно измениться около 50% битов
        if 100 < diff_bits < 156:  # от ~39% до ~61%
            print("✓ Лавинный эффект работает хорошо!")
            result = True
        elif diff_bits > 50:  # хотя бы больше 20%
            print("⚠ Лавинный эффект работает, но не оптимально")
            result = True
        else:
            print("✗ Лавинный эффект слишком слабый")
            result = False
    
    # Очистка
    os.unlink(file1)
    os.unlink(file2)
    return result

def test_output_to_file():
    """Тест записи вывода в файл"""
    print("\n" + "="*60)
    print("Дополнительный тест: Запись вывода в файл")
    print("="*60)
    
    test_data = b"Test output to file functionality"
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(test_data)
        input_file = f.name
    
    output_file = "test_output.hash"
    
    # Запускаем с выводом в файл
    cmd = f"python cryptocore.py dgst --algorithm sha256 --input {input_file} --output {output_file}"
    ret, out, err = run_command(cmd)
    
    if ret == 0:
        # Читаем из файла
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                file_content = f.read().strip()
            
            # Сравниваем с выводом в stdout (который должен быть пустым при --output)
            cmd = f"python cryptocore.py dgst --algorithm sha256 --input {input_file}"
            ret, stdout_hash, err = run_command(cmd)
            
            if ret == 0:
                stdout_hash = stdout_hash.split()[0]
                file_hash = file_content.split()[0]
                
                if stdout_hash == file_hash:
                    print(f"✓ Вывод в файл работает правильно")
                    print(f"  Хеш в файле: {file_hash}")
                    result = True
                else:
                    print(f"✗ Хеши не совпадают!")
                    print(f"  Stdout: {stdout_hash}")
                    print(f"  Файл:   {file_hash}")
                    result = False
            else:
                print(f"✗ Ошибка получения хеша: {err}")
                result = False
            
            # Удаляем тестовый файл
            os.unlink(output_file)
        else:
            print(f"✗ Выходной файл не создан!")
            result = False
    else:
        print(f"✗ Ошибка выполнения: {err}")
        result = False
    
    os.unlink(input_file)
    return result

def test_error_handling():
    """Тест обработки ошибок"""
    print("\n" + "="*60)
    print("Тест обработки ошибок")
    print("="*60)
    
    # Тест 1: Несуществующий файл
    print("\n1. Тест с несуществующим файлом:")
    cmd = "python cryptocore.py dgst --algorithm sha256 --input nonexistent_file.txt"
    ret, out, err = run_command(cmd)
    if ret != 0:
        print("✓ Правильно обработана ошибка отсутствующего файла")
        print(f"  Сообщение: {err}")
    else:
        print("✗ Не обработана ошибка отсутствующего файла")
    
    # Тест 2: Некорректный алгоритм
    print("\n2. Тест с некорректным алгоритмом:")
    cmd = "python cryptocore.py dgst --algorithm md5 --input test.txt"
    ret, out, err = run_command(cmd)
    if ret != 0:
        print("✓ Правильно обработана ошибка некорректного алгоритма")
        print(f"  Сообщение: {err}")
    else:
        print("✗ Не обработана ошибка некорректного алгоритма")
    
    # Тест 3: Отсутствует обязательный аргумент
    print("\n3. Тест без обязательного аргумента --input:")
    cmd = "python cryptocore.py dgst --algorithm sha256"
    ret, out, err = run_command(cmd)
    if ret != 0:
        print("✓ Правильно обработана ошибка отсутствия аргумента")
    else:
        print("✗ Не обработана ошибка отсутствия аргумента")
    
    return True

def main():
    """Основная функция запуска тестов"""
    print("="*70)
    print("ТЕСТИРОВАНИЕ ХЕШ-ФУНКЦИЙ CRYPTOCORE (Спринт 4)")
    print("="*70)
    
    tests = [
        ("Пустой файл", test_empty_file),
        ("Векторы NIST", test_nist_vectors),
        ("Совместимость", test_compatibility),
        ("Большой файл", test_large_file),
        ("Лавинный эффект", test_avalanche_effect),
        ("Вывод в файл", test_output_to_file),
        ("Обработка ошибок", test_error_handling),
    ]
    
    passed_tests = 0
    failed_tests = []
    
    for test_name, test_func in tests:
        try:
            print(f"\nЗапуск теста: {test_name}")
            if test_func():
                print(f"✓ Тест '{test_name}' ПРОЙДЕН")
                passed_tests += 1
            else:
                print(f"✗ Тест '{test_name}' НЕ ПРОЙДЕН")
                failed_tests.append(test_name)
        except Exception as e:
            print(f"✗ Тест '{test_name}' ВЫЗВАЛ ИСКЛЮЧЕНИЕ: {e}")
            failed_tests.append(test_name)
    
    # Итоги
    print("\n" + "="*70)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print("="*70)
    print(f"Всего тестов: {len(tests)}")
    print(f"Пройдено: {passed_tests}")
    print(f"Не пройдено: {len(failed_tests)}")
    
    if failed_tests:
        print("\nНе пройденные тесты:")
        for test in failed_tests:
            print(f"  - {test}")
        return 1
    else:
        print("\n✓ Все тесты успешно пройдены!")
        return 0

if __name__ == "__main__":
    sys.exit(main())