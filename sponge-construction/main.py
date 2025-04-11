import os

from ruped_keccak import RupedKeccak
from shake_hash import ShakeHash

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

if __name__ == "__main__":
    state_length_in_bytes = 200

    kdf = HKDF(
        algorithm=hashes.SHA512(),
        length=state_length_in_bytes,
        salt=b"salt",
        info=None
    )
    full = kdf.derive(os.urandom(32))
    iv = full[:136]
    key = full[136:]

    cipher = RupedKeccak(iv, key, ShakeHash())

    message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    print(f"Message: {message}")

    adata = b"Hello, world!"
    print(f"Associated data: {adata}")

    ciphertext, tag1 = cipher.encrypt(message, adata)
    print(f"Ciphertext: {ciphertext}")
    print(f"Tag: {tag1}")

    plaintext, tag2 = cipher.decrypt(ciphertext, adata)
    print(f"Plaintext: {plaintext}")

    print(f"Messages match?: {message == plaintext}")    
    print(f"Tags match?: {tag1 == tag2}")

    print("Testing tampering with the ciphertext")

    ciphertext = bytearray(ciphertext)
    ciphertext[0] = 0x00
    print(f"Tampered ciphertext: {bytes(ciphertext)}")
    plaintext, _ = cipher.decrypt(ciphertext, adata)
    print(f"Plaintext is null?: {plaintext == bytes()}")

    print("Testing altering the associated data")

    adata = bytearray(adata)
    adata[0] = 0x00
    print(f"Tampered associated data: {bytes(adata)}")
    plaintext, _ = cipher.decrypt(ciphertext, adata)
    print(f"Plaintext is null?: {plaintext == bytes()}")
