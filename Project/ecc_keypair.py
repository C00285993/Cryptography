from cryptography.hazmat.primitives.asymmetric import ec
import time


before = time.perf_counter()

private_key = ec.generate_private_key(
    ec.SECP521R1()  
)

after = time.perf_counter()
print(f" {after - before:.4f} seconds")
