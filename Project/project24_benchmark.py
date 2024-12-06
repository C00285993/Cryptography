import os
import time
import csv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding


# --- Utility Function for Timing ---
def time_execution(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, end - start


# --- Keypair Generation Benchmarks ---
def benchmark_keypair_generation():
    results = []

    # RSA Keypair Generation
    rsa_key_sizes = [1024, 2048, 3072, 7680, 15360]
    for size in rsa_key_sizes:
        _, duration = time_execution(rsa.generate_private_key, public_exponent=65537, key_size=size)
        results.append(("RSA", size, duration))
        print(f"RSA {size}-bit key generated in {duration:.4f} seconds")

    # DSA Keypair Generation
    dsa_key_sizes = [1024, 2048, 3072, 4096]
    for size in dsa_key_sizes:
        _, duration = time_execution(dsa.generate_private_key, key_size=size)
        results.append(("DSA", size, duration))
        print(f"DSA {size}-bit key generated in {duration:.4f} seconds")

    # ECC Keypair Generation
    ecc_curves = [
        (ec.SECP192R1(), 192),
        (ec.SECP224R1(), 224),
        (ec.SECP256R1(), 256),
        (ec.SECP384R1(), 384),
        (ec.SECP521R1(), 521),
    ]
    for curve, size in ecc_curves:
        _, duration = time_execution(ec.generate_private_key, curve=curve)
        results.append(("ECC", size, duration))
        print(f"ECC {size}-bit key generated in {duration:.4f} seconds")

    return results


# --- RSA Encryption and Decryption Benchmarks ---
def benchmark_rsa_operations(rsa_key_sizes, data):
    encryption_results = []
    decryption_results = []

    # Generate Keys
    rsa_keys = {size: rsa.generate_private_key(public_exponent=65537, key_size=size) for size in rsa_key_sizes}

    # Encrypt and Decrypt
    for size, private_key in rsa_keys.items():
        pub_key = private_key.public_key()
        max_chunk_size = (size // 8) - 2 * (256 // 8) - 2

        # Encryption
        ciphertext_chunks, encryption_time = time_execution(chunk_rsa_encrypt, pub_key, data, max_chunk_size)
        encryption_results.append((size, encryption_time))
        print(f"RSA {size}-bit encryption: {encryption_time:.4f} seconds")

        # Decryption
        _, decryption_time = time_execution(chunk_rsa_decrypt, private_key, ciphertext_chunks, max_chunk_size)
        decryption_results.append((size, decryption_time))
        print(f"RSA {size}-bit decryption: {decryption_time:.4f} seconds")

    return encryption_results, decryption_results


# --- Digital Signing and Verification Benchmarks ---
def benchmark_signing_and_verification():
    results = []

    test_message = os.urandom(50)

    # RSA Signing and Verification
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature, signing_time = time_execution(
        rsa_key.sign,
        test_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    results.append(("RSA", 2048, "Signing", signing_time))
    print(f"RSA signing in {signing_time:.4f} seconds")

    _, verification_time = time_execution(
        rsa_key.public_key().verify,
        signature,
        test_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    results.append(("RSA", 2048, "Verification", verification_time))
    print(f"RSA verification in {verification_time:.4f} seconds")

    # DSA Signing and Verification
    dsa_key_sizes = [1024, 2048, 3072, 4096]
    for size in dsa_key_sizes:
        dsa_key = dsa.generate_private_key(key_size=size)
        signature, signing_time = time_execution(dsa_key.sign, test_message, hashes.SHA256())
        results.append(("DSA", size, "Signing", signing_time))
        print(f"DSA {size}-bit signing in {signing_time:.4f} seconds")

        _, verification_time = time_execution(dsa_key.public_key().verify, signature, test_message, hashes.SHA256())
        results.append(("DSA", size, "Verification", verification_time))
        print(f"DSA {size}-bit verification in {verification_time:.4f} seconds")

    # ECC Signing and Verification
    ecc_curves = [
        (ec.SECP192R1(), 192),
        (ec.SECP224R1(), 224),
        (ec.SECP256R1(), 256),
        (ec.SECP384R1(), 384),
        (ec.SECP521R1(), 521),
    ]
    for curve, size in ecc_curves:
        ecc_key = ec.generate_private_key(curve)
        signature, signing_time = time_execution(ecc_key.sign, test_message, ec.ECDSA(hashes.SHA256()))
        results.append(("ECC", size, "Signing", signing_time))
        print(f"ECC {size}-bit signing in {signing_time:.4f} seconds")

        _, verification_time = time_execution(ecc_key.public_key().verify, signature, test_message, ec.ECDSA(hashes.SHA256()))
        results.append(("ECC", size, "Verification", verification_time))
        print(f"ECC {size}-bit verification in {verification_time:.4f} seconds")

    return results


# --- Chunked RSA Encryption and Decryption ---
def chunk_rsa_encrypt(public_key, plaintext, chunk_size):
    ciphertext_chunks = []
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
    return ciphertext_chunks


def chunk_rsa_decrypt(private_key, ciphertext_chunks, chunk_size):
    plaintext_chunks = []
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
    return b"".join(plaintext_chunks)


# --- Main Function ---
if __name__ == "__main__":
    # Keypair Generation Benchmarks
    keypair_results = benchmark_keypair_generation()

    # RSA Encryption/Decryption Benchmarks
    rsa_key_sizes = [1024, 2048, 3072, 7680, 15360]
    test_data = os.urandom(10 * 1024)  # 10KB of data
    rsa_encryption_results, rsa_decryption_results = benchmark_rsa_operations(rsa_key_sizes, test_data)

    # Signing and Verification Benchmarks
    signing_verification_results = benchmark_signing_and_verification()
