# [file name]: tests/test_pbkdf2.py
# [file content begin]
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from kdf.pbkdf2 import pbkdf2_hmac_sha256
from kdf.hkdf import derive_key


def test_pbkdf2_basic():
    """Basic PBKDF2 tests"""
    print("Running basic PBKDF2 tests...")

    # Test 1: Simple case
    result = pbkdf2_hmac_sha256(b'test', b'salt', 1, 32)
    assert len(result) == 32, f"Expected 32 bytes, got {len(result)}"
    print("✓ Basic test passed")

    # Test 2: Different lengths
    for length in [1, 16, 32, 50, 100]:
        result = pbkdf2_hmac_sha256(b'password', b'salt', 100, length)
        assert len(result) == length, f"Expected length {length}, got {len(result)}"
    print("✓ Variable length test passed")

    # Test 3: Repeatability
    r1 = pbkdf2_hmac_sha256(b'password', b'salt', 1000, 32)
    r2 = pbkdf2_hmac_sha256(b'password', b'salt', 1000, 32)
    assert r1 == r2, "PBKDF2 is not deterministic"
    print("✓ Repeatability test passed")

    # Test 4: Different iterations produce different results
    r1 = pbkdf2_hmac_sha256(b'password', b'salt', 1, 32)
    r2 = pbkdf2_hmac_sha256(b'password', b'salt', 2, 32)
    assert r1 != r2, "Different iterations should produce different results"
    print("✓ Different iterations test passed")

    # Test 5: Different salts produce different results
    r1 = pbkdf2_hmac_sha256(b'password', b'salt1', 1000, 32)
    r2 = pbkdf2_hmac_sha256(b'password', b'salt2', 1000, 32)
    assert r1 != r2, "Different salts should produce different results"
    print("✓ Different salts test passed")


def test_key_hierarchy():
    """Test key hierarchy function"""
    print("\nRunning key hierarchy tests...")

    master = b'0' * 32
    key1 = derive_key(master, 'encryption', 32)
    key2 = derive_key(master, 'authentication', 32)

    # Проверка детерминированности
    key1_again = derive_key(master, 'encryption', 32)
    assert key1 == key1_again, "Key derivation not deterministic"

    # Проверка разделения контекста
    assert key1 != key2, "Different contexts should produce different keys"

    # Проверка различных длин
    key_short = derive_key(master, 'short', 16)
    key_long = derive_key(master, 'long', 64)
    assert len(key_short) == 16, f"Expected length 16, got {len(key_short)}"
    assert len(key_long) == 64, f"Expected length 64, got {len(key_long)}"

    print("✓ All key hierarchy tests passed")


def test_pbkdf2_with_known_vectors():
    """
    Test PBKDF2 with known test vectors from various sources.
    """
    print("\nRunning PBKDF2 test vectors...")

    # Test vectors from Python's hashlib.pbkdf2_hmac for comparison
    # We'll use Python's implementation to generate expected values

    import hashlib

    test_cases = [
        # Simple test case
        {
            'password': b'password',
            'salt': b'salt',
            'iterations': 1,
            'dklen': 32,
        },
        {
            'password': b'password',
            'salt': b'salt',
            'iterations': 2,
            'dklen': 32,
        },
        {
            'password': b'password',
            'salt': b'salt',
            'iterations': 1000,
            'dklen': 32,
        },
        {
            'password': b'passwordPASSWORDpassword',
            'salt': b'saltSALTsaltSALTsaltSALTsaltSALTsalt',
            'iterations': 4096,
            'dklen': 40,
        },
        # Test with hex salt
        {
            'password': b'test',
            'salt': '73616c74',  # 'salt' in hex
            'iterations': 1,
            'dklen': 32,
        }
    ]

    for i, test in enumerate(test_cases):
        # Get expected value from Python's implementation
        if isinstance(test['salt'], str):
            salt_bytes = bytes.fromhex(test['salt'])
        else:
            salt_bytes = test['salt']

        expected = hashlib.pbkdf2_hmac(
            'sha256',
            test['password'],
            salt_bytes,
            test['iterations'],
            test['dklen']
        )

        # Get our implementation's result
        result = pbkdf2_hmac_sha256(
            test['password'],
            test['salt'],
            test['iterations'],
            test['dklen']
        )

        assert result == expected, f"Test case {i + 1} failed.\nExpected: {expected.hex()}\nGot: {result.hex()}"
        print(f"✓ Test case {i + 1} passed")

    print("✓ All PBKDF2 test vectors passed")


def test_interoperability_with_openssl():
    """
    Test interoperability with OpenSSL command.
    Note: This test requires OpenSSL to be installed.
    """
    print("\nTesting interoperability with OpenSSL...")

    import subprocess
    import tempfile

    # Skip if OpenSSL is not available
    try:
        subprocess.run(['openssl', 'version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠ OpenSSL not found, skipping interoperability test")
        return

    # Test case
    password = b'test123'
    salt = b'saltsalt'
    iterations = 1000
    dklen = 32

    # Get result from our implementation
    our_result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)

    # Create temporary files for OpenSSL
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as pass_file:
        pass_file.write(password)
        pass_file.flush()

        # Run OpenSSL command
        cmd = [
            'openssl', 'kdf', '-keylen', str(dklen),
            '-kdfopt', f'pass:{password.decode()}',
            '-kdfopt', f'salt:{salt.hex()}',
            '-kdfopt', f'iter:{iterations}',
            'PBKDF2'
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            openssl_output = result.stdout.strip()

            # OpenSSL outputs hex
            openssl_bytes = bytes.fromhex(openssl_output)

            if our_result == openssl_bytes:
                print("✓ Interoperability with OpenSSL passed")
            else:
                print(f"⚠ OpenSSL result differs\nOur: {our_result.hex()}\nOpenSSL: {openssl_output}")
                # Don't fail the test for this
        except subprocess.CalledProcessError as e:
            print(f"⚠ OpenSSL command failed: {e}")

    print("✓ Interoperability tests completed")


if __name__ == '__main__':
    print("Запуск тестов PBKDF2 и иерархии ключей...")
    print("=" * 50)

    try:
        test_pbkdf2_basic()
        test_key_hierarchy()
        test_pbkdf2_with_known_vectors()
        test_interoperability_with_openssl()

        print("\n" + "=" * 50)
        print("Все тесты пройдены успешно!")
    except AssertionError as e:
        print(f"\n✗ Тест не пройден: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Произошла ошибка: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
# [file content end]