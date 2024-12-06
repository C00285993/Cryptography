from cryptography.hazmat.primitives.asymmetric import dsa
import time


before = time.perf_counter()

private_key = dsa.generate_private_key(
    key_size=4096  
)
public_key = private_key.public_key()

after = time.perf_counter()


print(f"{after - before:0.4f} seconds")
