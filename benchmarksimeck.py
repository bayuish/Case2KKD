import time
import base64
import random
from Crypto.Random import get_random_bytes

# --- Simeck Cipher CFB Mode ---
class SimeckCFB:
    def __init__(self, key: bytes, iv: bytes):
        self.rounds = 32
        self.block_size = 8  # 64-bit
        self.key = key
        self.iv = iv

    def rol(self, x, r):
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

    def ror(self, x, r):
        return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF

    def simeck_encrypt(self, block: int, key: int) -> int:
        left = (block >> 32) & 0xFFFFFFFF
        right = block & 0xFFFFFFFF

        for _ in range(self.rounds):
            tmp = left
            left = right ^ (self.rol(left, 1) & self.rol(left, 8)) ^ self.rol(left, 2) ^ key
            right = tmp

        return ((left << 32) | right) & 0xFFFFFFFFFFFFFFFF

    def encrypt(self, plaintext: str) -> str:
        ciphertext = b''
        prev = int.from_bytes(self.iv, 'big')
        key_int = int.from_bytes(self.key[:8], 'big')  # 64-bit key
        plaintext_bytes = plaintext.encode()

        for byte in plaintext_bytes:
            keystream = self.simeck_encrypt(prev, key_int)
            ct_byte = byte ^ ((keystream >> 56) & 0xFF)
            ciphertext += bytes([ct_byte])
            prev = ((prev << 8) | ct_byte) & 0xFFFFFFFFFFFFFFFF

        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = b''
        prev = int.from_bytes(self.iv, 'big')
        key_int = int.from_bytes(self.key[:8], 'big')

        for byte in ciphertext:
            keystream = self.simeck_encrypt(prev, key_int)
            pt_byte = byte ^ ((keystream >> 56) & 0xFF)
            plaintext += bytes([pt_byte])
            prev = ((prev << 8) | byte) & 0xFFFFFFFFFFFFFFFF

        return plaintext.decode()

# --- Benchmark Function ---
def benchmark_simeck_computation():
    key_sizes = [8, 16, 24]  # bytes (64-bit, 128-bit, 192-bit)
    plaintext_sizes = [50, 100, 150, 200, 250]
    sample_size = 100

    print(f"{'Key Size':<10}{'Plaintext Size':<16}{'Enc Delay (ms)':<16}{'Dec Delay (ms)':<16}")

    for key_size in key_sizes:
        key = get_random_bytes(key_size)
        iv = get_random_bytes(8)

        for pt_len in plaintext_sizes:
            total_enc = 0
            total_dec = 0

            for _ in range(sample_size):
                message = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890', k=pt_len))
                cipher = SimeckCFB(key, iv)

                # Encryption timing
                start_enc = time.time()
                encrypted = cipher.encrypt(message)
                end_enc = time.time()

                # Decryption timing
                start_dec = time.time()
                decrypted = cipher.decrypt(encrypted)
                end_dec = time.time()

                assert decrypted == message, "Decryption failed"

                total_enc += (end_enc - start_enc)
                total_dec += (end_dec - start_dec)

            avg_enc = (total_enc / sample_size) * 1000  # ms
            avg_dec = (total_dec / sample_size) * 1000  # ms
            print(f"{key_size*8:<10}{pt_len:<16}{avg_enc:<16.3f}{avg_dec:<16.3f}")

# --- Run Benchmark ---
if __name__ == "__main__":
    benchmark_simeck_computation()
