import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- RSA Encryption with Timing ---
def rsa_encrypt(public_key, plaintext, chunk_size):
    ciphertext_chunks = []
    start_time = time.perf_counter()
    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i:i + chunk_size]
        ciphertext = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext_chunks.append(ciphertext)
    end_time = time.perf_counter()
    return ciphertext_chunks, end_time - start_time

# --- Main Function ---
if __name__ == "__main__":
    rsa_key_sizes = [1024, 2048, 3072, 7680, 15360]  # Key sizes for 80-, 112-, 128-, 192-, 256-bit security
    plaintext = os.urandom(100)  # 100-byte random plaintext

    for rsa_key_size in rsa_key_sizes:
        # Generate RSA Keypair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_size)
        public_key = private_key.public_key()

        # Calculate maximum chunk size
        max_chunk_size = (rsa_key_size // 8) - 2 * (256 // 8) - 2

        # Encrypt the plaintext and measure time
        ciphertext, encryption_time = rsa_encrypt(public_key, plaintext, max_chunk_size)
        print(f"RSA {rsa_key_size}-bit encryption time: {encryption_time:.4f} seconds")
