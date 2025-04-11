import os

from ruped_tweakable import RupedTweakable

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

if __name__ == "__main__":
    key_size_in_bytes = 16

    kdf = HKDF(
        algorithm=hashes.SHA512(),
        length=key_size_in_bytes,
        salt=b"salt",
        info=None
    ) 
    key = kdf.derive(os.urandom(32))

    cipher = RupedTweakable(key)

    message = b"Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo."
    print(f"Message: {message}")

    ciphertext, tag1, nounce = cipher.encrypt(message)
    print(f"Ciphertext: {ciphertext}")
    print(f"Tag: {tag1}")

    plaintext, tag2 = cipher.decrypt(ciphertext, nounce)
    print(f"Plaintext: {plaintext}")

    print(f"Messages match?: {message == plaintext}")
    print(f"Tags match?: {tag1 == tag2}")

    print("Testing removing a given block")

    ciphertext = bytearray(ciphertext)
    ciphertext = ciphertext[16:]
    print(f"Tampered ciphertext: {bytes(ciphertext)}")
    plaintext2, _ = cipher.decrypt(ciphertext, nounce)
    print(f"Plaintext: {plaintext2}")
    print(f"Decryption failed?: {plaintext != plaintext2}")
