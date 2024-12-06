from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os
import time

before = time.perf_counter()
private_key = rsa.generate_private_key(
public_exponent=65537,
key_size=15360	
)
public_key = private_key.public_key()



after = time.perf_counter()
print(f"{after - before:0.4f} seconds")
