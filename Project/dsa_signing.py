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

# --- DSA Signing Benchmark ---
def dsa_signing_benchmark():
    results = []
    dsa_key_sizes = [1024, 2048, 3072, 4096]
    test_message = os.urandom(50)  # Random 50-byte message

    for size in dsa_key_sizes:
        # Generate DSA Keypair
        private_key = dsa.generate_private_key(key_size=size)

        # Signing
        _, signing_time = time_execution(private_key.sign, test_message, hashes.SHA256())
        results.append(("DSA", size, "Signing", signing_time))
        print(f"DSA {size}-bit signing in {signing_time:.4f} seconds")

    return results

# --- Main Function ---
if __name__ == "__main__":
    dsa_signing_results = dsa_signing_benchmark()

    # Print Summary
    print("\nSummary of DSA Signing:")
    for algorithm, size, operation, duration in dsa_signing_results:
        print(f"{algorithm} {size}-bit {operation}: {duration:.4f} seconds")
