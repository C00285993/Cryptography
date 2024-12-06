import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# --- Utility Function for Timing ---
def time_execution(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, end - start

# --- ECC Verification Benchmark ---
def ecc_verification_benchmark():
    results = []
    ecc_curves = [
        (ec.SECP192R1(), 192),
        (ec.SECP224R1(), 224),
        (ec.SECP256R1(), 256),
        (ec.SECP384R1(), 384),
        (ec.SECP521R1(), 521),
    ]
    test_message = os.urandom(50)  # Random 50-byte message

    for curve, size in ecc_curves:
        # Generate ECC Keypair
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()

        # Signing
        signature = private_key.sign(test_message, ec.ECDSA(hashes.SHA256()))

        # Verification
        _, verification_time = time_execution(public_key.verify, signature, test_message, ec.ECDSA(hashes.SHA256()))
        results.append(("ECC", size, "Verification", verification_time))
        print(f"ECC {size}-bit verification in {verification_time:.4f} seconds")

    return results

# --- Main Function ---
if __name__ == "__main__":
    ecc_verification_results = ecc_verification_benchmark()

    # Print Summary
    print("\nSummary of ECC Verification:")
    for algorithm, size, operation, duration in ecc_verification_results:
        print(f"{algorithm} {size}-bit {operation}: {duration:.4f} seconds")
