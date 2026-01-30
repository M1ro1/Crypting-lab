import time
from backend.md5_hash import hash_string
from backend.generator import lcg_generate

W = 64
R = 16
B_BYTES = 16
W_BYTES = W // 8
BLOCK_SIZE = 16

P_W = 0xB7E151628AED2A6B
Q_W = 0x9E3779B97F4A7C15
MASK = 0xFFFFFFFFFFFFFFFF
MASK_2 = 0xFFFFFFFF

def left_slide(x, y):
    y = y % W
    return ((x << y) | (x >> (W - y))) & MASK

def right_slide(x, y):
    y = y % W
    return ((x >> y) | (x << (W - y))) & MASK

def get_key_from_password(password):
    hash_md5 = hash_string(password)
    return bytes.fromhex(hash_md5)

def generate_iv():
    seed = int(time.time() * 1000) & MASK_2
    a, c, m = 1103515245, 12345, 2 ** 31
    seq = lcg_generate(a, c, m, seed, 4)
    iv = b''
    for num in seq:
        iv += num.to_bytes(4, 'little')
    return iv

class RC5:
    def __init__(self, key_bytes):
        self.S = self._key_exp(key_bytes)

    @staticmethod
    def _key_exp(key):
        u = W_BYTES
        c = len(key) // u
        if len(key) % u != 0: c += 1

        L = [0] * c
        for i in range(len(key)):
            L[i // u] = (L[i // u] + (key[i] << (8 * (i % u)))) & MASK

        t = 2 * (R + 1)
        S = [0] * t
        S[0] = P_W
        for i in range(1, t):
            S[i] = (S[i - 1] + Q_W) & MASK

        i = j = 0
        A = B = 0
        loops = 3 * max(t, c)
        for _ in range(loops):
            A = S[i] = left_slide((S[i] + A + B) & MASK, 3)
            B = L[j] = left_slide((L[j] + A + B) & MASK, (A + B))
            i = (i + 1) % t
            j = (j + 1) % c
        return S

    def encrypt_block(self, data_block):
        A = int.from_bytes(data_block[:W_BYTES], 'little')
        B = int.from_bytes(data_block[W_BYTES:], 'little')

        A = (A + self.S[0]) & MASK
        B = (B + self.S[1]) & MASK

        for i in range(1, R + 1):
            A = (left_slide((A ^ B), B) + self.S[2 * i]) & MASK
            B = (left_slide((B ^ A), A) + self.S[2 * i + 1]) & MASK

        res = A.to_bytes(W_BYTES, 'little') + B.to_bytes(W_BYTES, 'little')
        return res

    def decrypt_block(self, data_block):
        A = int.from_bytes(data_block[:W_BYTES], 'little')
        B = int.from_bytes(data_block[W_BYTES:], 'little')

        for i in range(R, 0, -1):
            B = right_slide((B - self.S[2 * i + 1]) & MASK, A) ^ A
            A = right_slide((A - self.S[2 * i]) & MASK, B) ^ B

        B = (B - self.S[1]) & MASK
        A = (A - self.S[0]) & MASK

        res = A.to_bytes(W_BYTES, 'little') + B.to_bytes(W_BYTES, 'little')
        return res


def pad_data(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def unpad_data(data):
    if not data:
        return b''
    pad_len = data[-1]
    if pad_len > BLOCK_SIZE or pad_len == 0:
        raise ValueError("Некоректний паддінг")
    return data[:-pad_len]


def encrypt_file_rc5(input_path, output_path, password):
    key = get_key_from_password(password)
    cipher = RC5(key)

    iv = generate_iv()
    encrypted_iv = cipher.encrypt_block(iv)

    with open(input_path, 'rb') as f:
        data = f.read()

    data = pad_data(data)

    with open(output_path, 'wb') as f_out:
        f_out.write(encrypted_iv)

        prev_block = iv

        for i in range(0, len(data), BLOCK_SIZE):
            chunk = data[i: i + BLOCK_SIZE]

            xor_block = bytes(a ^ b for a, b in zip(chunk, prev_block))

            encrypted_block = cipher.encrypt_block(xor_block)

            f_out.write(encrypted_block)

            prev_block = encrypted_block


def decrypt_file_rc5(input_path, output_path, password):
    key = get_key_from_password(password)
    cipher = RC5(key)

    with open(input_path, 'rb') as f_in:
        file_content = f_in.read()

    if len(file_content) < BLOCK_SIZE:
        raise ValueError("Файл занадто малий")

    encrypted_iv = file_content[:BLOCK_SIZE]
    ciphertext = file_content[BLOCK_SIZE:]

    iv = cipher.decrypt_block(encrypted_iv)

    decrypted_data = b''
    prev_block = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        chunk = ciphertext[i: i + BLOCK_SIZE]

        if len(chunk) != BLOCK_SIZE:
            break

        decrypted_part = cipher.decrypt_block(chunk)

        plain_block = bytes(a ^ b for a, b in zip(decrypted_part, prev_block))

        decrypted_data += plain_block
        prev_block = chunk

    final_data = unpad_data(decrypted_data)

    with open(output_path, 'wb') as f_out:
        f_out.write(final_data)