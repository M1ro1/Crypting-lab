A = 0x67452301
B = 0xEFCDAB89
C = 0x98BADCFE
D = 0x10325476

T = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
]


class MD5:
    def __init__(self, data=None):
        self.state = [A, B, C, D]
        self.count = 0
        self.buffer = b''

        if data:
            self.update(data)

    def _rotate_left(self, x, n):
        return (((x << n) | (x >> (32 - n))) & 0xFFFFFFFF)

    def _bytes_to_words(self, block):
        words = []
        for i in range(0, 64, 4):
            word = block[i] | (block[i + 1] << 8) | (block[i + 2] << 16) | (block[i + 3] << 24)
            words.append(word)
        return words

    def _md5_process(self, block):
        M = self._bytes_to_words(block)
        a, b, c, d = self.state
        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            temp = (a + f + T[i] + M[g]) & 0xFFFFFFFF
            a = d
            d = c
            c = b
            b = (b + self._rotate_left(temp, S[i])) & 0xFFFFFFFF

        self.state[0] = (self.state[0] + a) & 0xFFFFFFFF
        self.state[1] = (self.state[1] + b) & 0xFFFFFFFF
        self.state[2] = (self.state[2] + c) & 0xFFFFFFFF
        self.state[3] = (self.state[3] + d) & 0xFFFFFFFF

    def _md5_pad(self):
        self.buffer += b'\x80'
        msg_len_bytes = len(self.buffer)
        padding_len = (56 - (msg_len_bytes % 64)) % 64
        self.buffer += b'\x00' * padding_len

        original_length_bits = self.count

        length_bytes = original_length_bits.to_bytes(8, 'little')
        self.buffer += length_bytes

    def update(self, data):
        self.buffer += data
        self.count += len(data) * 8

        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            self._md5_process(block)
            self.buffer = self.buffer[64:]

    def hexdigest(self):
        temp_state = list(self.state)
        temp_buffer = self.buffer

        self._md5_pad()

        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            self._md5_process(block)
            self.buffer = self.buffer[64:]

        result = b''
        for s in self.state:
            result += s.to_bytes(4, 'little')

        self.state = temp_state
        self.buffer = temp_buffer

        return result.hex().upper()


def hash_string(input_str):
    md5_obj = MD5(input_str.encode('utf-8'))
    return md5_obj.hexdigest()

def hash_file(filepath):
    md5_obj = MD5()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5_obj.update(chunk)
        return md5_obj.hexdigest()
    except FileNotFoundError:
        print(f"Помилка: Файл {filepath} не знайдено.")
        return None

def verify_file(filepath, expected_hash):
    computed_hash = hash_file(filepath)
    if computed_hash is None:
        return False
    return computed_hash == expected_hash.upper()