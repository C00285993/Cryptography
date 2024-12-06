import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- RSA Decryption with Timing ---
def rsa_decrypt(private_key, ciphertext_chunks):
    plaintext_chunks = []
    start_time = time.perf_counter()
    for chunk in ciphertext_chunks:
        plaintext = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        plaintext_chunks.append(plaintext)
    end_time = time.perf_counter()
    return b"".join(plaintext_chunks), end_time - start_time

# --- Main Function ---
if __name__ == "__main__":
    rsa_key_sizes = [1024, 2048, 3072, 7680, 15360]  # Key sizes for 80-, 112-, 128-, 192-, 256-bit security
    plaintext = os.urandom(100)  # 100-byte random plaintext

    for rsa_key_size in rsa_key_sizes:
        # Generate RSA Keypair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_size)
        public_key = private_key.public_key()

        # Encrypt the plaintext
        max_chunk_size = (rsa_key_size // 8) - 2 * (256 // 8) - 2
        ciphertext_chunks = []
        for i in range(0, len(plaintext), max_chunk_size):
            chunk = plaintext[i:i + max_chunk_size]
            ciphertext = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            ciphertext_chunks.append(ciphertext)

        # Decrypt the ciphertext and measure time
        decrypted_plaintext, decryption_time = rsa_decrypt(private_key, ciphertext_chunks)
        print(f"RSA {rsa_key_size}-bit decryption time: {decryption_time:.4f} seconds")
