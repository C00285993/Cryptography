import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --- Utility Function for Timing ---
def time_execution(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, end - start

# --- RSA Signing Benchmark ---
def rsa_signing_benchmark():
    results = []
    rsa_key_sizes = [1024, 2048, 3072, 7680, 15360]
    test_message = os.urandom(50)  # Random 50-byte message

    for size in rsa_key_sizes:
        # Generate RSA Keypair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)

        # Signing
        _, signing_time = time_execution(
            private_key.sign,
            test_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        results.append(("RSA", size, "Signing", signing_time))
        print(f"RSA {size}-bit signing in {signing_time:.4f} seconds")

    return results

# --- Main Function ---
if __name__ == "__main__":
    rsa_signing_results = rsa_signing_benchmark()

    # Print Summary
    print("\nSummary of RSA Signing:")
    for algorithm, size, operation, duration in rsa_signing_results:
        print(f"{algorithm} {size}-bit {operation}: {duration:.4f} seconds")
