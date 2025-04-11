from typing import Any, Tuple

from sage.all import *

from elgamal_fo import ElGamalFO
from utils import (
    ElGamalPrivateKey,
    ElGamalPublicKey,
    from_bytes,
    to_bytes,
    xor,
)

class ElGamalKEM:
    """
    Key encapsulation mechanism (KEM) based on the ElGamal cryptosystem.

    Simply generates a random key and encrypts it using the ElGamalFO class.
    """
    def __init__(self, lambda_value: int):
        self.lambda_value = lambda_value

        # Base this class on the ElGamalFO class
        self._elgamal_fo = ElGamalFO(lambda_value)

    def generate_key_pair(self) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
        return self._elgamal_fo.generate_key_pair()

    def kem(self, public_key: ElGamalPublicKey) -> Tuple[int, Any]:
        _, q, _, _ = public_key

        k = randint(1, q - 1)

        return k, self._elgamal_fo.encrypt(public_key, to_bytes(k))

    def krev(
        self, private_key: ElGamalPrivateKey, ciphertext: Tuple[int, Tuple[int, int]]
    ) -> int:
        k = self._elgamal_fo.decrypt(private_key, ciphertext)
        return from_bytes(k)

def main() -> None:
    lambda_value: int = 128
    elgamal_kem = ElGamalKEM(lambda_value)

    print(f"Generating keys with security parameter lambda = {lambda_value} bits")
    public_key, private_key = elgamal_kem.generate_key_pair()
    print(f"Public key (p, q, g, h): {public_key}")
    print(f"Private key x: {private_key}")

    print()

    k, ciphertext = elgamal_kem.kem(public_key)
    print(f"Encapsulated key: {k}")
    print(f"Ciphertext: {ciphertext}")

    print()

    krev = elgamal_kem.krev(private_key, ciphertext)
    print(f"Decapsulated key: {krev}")
    print(f"Are the keys equal? {k == krev}")

    print()

    print("Demonstration of the KEM using an OTP")
    message = b"Hello, world!"
    print(f"Message: {message}")

    print()

    ciphertext = xor(message, to_bytes(k))
    print(f"Ciphertext: {ciphertext}")

    print()

    decrypted_message = xor(ciphertext, to_bytes(k))
    print(f"Decrypted message: {decrypted_message}")
    print(f"Are the messages equal? {message == decrypted_message}")

if __name__ == "__main__":
    main()
