import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa

# --- Utility Function for Timing ---
def time_execution(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, end - start

# --- DSA Verification Benchmark ---
def dsa_verification_benchmark():
    results = []
    dsa_key_sizes = [1024, 2048, 3072, 4096]
    test_message = os.urandom(50)  # Random 50-byte message

    for size in dsa_key_sizes:
        # Generate DSA Keypair
        private_key = dsa.generate_private_key(key_size=size)
        public_key = private_key.public_key()

        # Signing
        signature = private_key.sign(test_message, hashes.SHA256())

        # Verification
        _, verification_time = time_execution(public_key.verify, signature, test_message, hashes.SHA256())
        results.append(("DSA", size, "Verification", verification_time))
        print(f"DSA {size}-bit verification in {verification_time:.4f} seconds")

    return results

# --- Main Function ---
if __name__ == "__main__":
    dsa_verification_results = dsa_verification_benchmark()

    # Print Summary
    print("\nSummary of DSA Verification:")
    for algorithm, size, operation, duration in dsa_verification_results:
        print(f"{algorithm} {size}-bit {operation}: {duration:.4f} seconds")
