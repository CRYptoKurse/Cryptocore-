class SHA256:
    def __init__(self):
        # Инициализировать значения хеша (первые 32 бита дробных частей квадратных корней первых 8 простых чисел)
        self.h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        # Инициализировать константы раундов (первые 32 бита дробных частей кубических корней первых 64 простых чисел)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        self.data = bytearray()
        self.total_length = 0

    def _rotr(self, x, n):
        return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

    def _sha256_sigma0(self, x):
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ (x >> 3)

    def _sha256_sigma1(self, x):
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ (x >> 10)

    def _sha256_Sigma0(self, x):
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)

    def _sha256_Sigma1(self, x):
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)

    def _ch(self, x, y, z):
        return (x & y) ^ (~x & z)

    def _maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def padding(self):
        """Реализовать дополнение SHA-256"""
        length = len(self.data)
        self.total_length += length
        
        # Добавить бит '1'
        self.data.append(0x80)
        
        # Добавить нули пока длина не будет ≡ 56 mod 64
        while (len(self.data) % 64) != 56:
            self.data.append(0x00)
        
        # Добавить длину сообщения как 64-битное big-endian число
        bit_length = self.total_length * 8
        self.data.extend(bit_length.to_bytes(8, 'big'))
        
        return self.data

    def process_block(self, block):
        """Обработать один 512-битный блок"""
        w = [0] * 64
        
        # Разбить блок на 16 слов по 32 бита
        for i in range(16):
            w[i] = int.from_bytes(block[i*4:(i+1)*4], 'big')
        
        # Расширить первые 16 слов в остальные 48 слов
        for i in range(16, 64):
            s0 = self._sha256_sigma0(w[i-15])
            s1 = self._sha256_sigma1(w[i-2])
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
        
        # Инициализировать рабочие переменные текущими значениями хеша
        a, b, c, d, e, f, g, h = self.h
        
        # Главный цикл сжатия
        for i in range(64):
            Sigma1 = self._sha256_Sigma1(e)
            ch = self._ch(e, f, g)
            temp1 = (h + Sigma1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            Sigma0 = self._sha256_Sigma0(a)
            maj = self._maj(a, b, c)
            temp2 = (Sigma0 + maj) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Добавить сжатый блок к текущему хешу
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def update(self, message):
        """Обработать сообщение блоками"""
        self.data.extend(message)

    def digest(self):
        """Вернуть финальный хеш"""
        # Применить дополнение
        padded_data = self.padding()
        
        # Обработать все блоки
        for i in range(0, len(padded_data), 64):
            block = padded_data[i:i+64]
            self.process_block(block)
        
        # Собрать финальный хеш
        result = bytearray()
        for val in self.h:
            result.extend(val.to_bytes(4, 'big'))
        
        return bytes(result)

    def hexdigest(self):
        """Вернуть хеш в виде шестнадцатеричной строки"""
        return self.digest().hex()