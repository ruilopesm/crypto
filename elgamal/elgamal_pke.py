from random import randint
from typing import Tuple

from sage.all import *

from utils import (
    ElGamalPrivateKey,
    ElGamalPublicKey,
    map_message_to_group,
    unmap_message_from_group,
)

class ElGamalPKE:
    """
    PKE IND-CPA scheme based on the ElGamal cryptosystem. This is not secure
    under a chosen ciphertext attack (IND-CCA), since the encryption is
    homomorphic. For example, given two ciphertexts (c1, c2) of some possible
    unknown message m, one can easily compute a valid encryption (c1, 2 * c2)
    of the message 2 * m.

    Encryption is a probabilistic algorithm, meaning that the same plaintext
    will not always result in the same ciphertext. In fact, there are
    2 ^ lambda possible ciphertexts for a given plaintext.

    The security of the ElGamal cryptosystem lies in the hardness of the
    Discrete Logarithm Problem (DLP) in the multiplicative group of integers
    modulo p, where p is a large prime number.
    """
    def __init__(self, lambda_value: int):
        self.lambda_value = lambda_value
        self._generate_parameters()

    def generate_key_pair(self) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
        x = randint(1, self.q - 1)
        private_key = x

        h = power_mod(self.g, x, self.p)
        self.h = h
        public_key: ElGamalPublicKey = (self.p, self.q, self.g, h)

        return public_key, private_key

    def encrypt(
        self, public_key: ElGamalPublicKey, plaintext: bytes
    ) -> Tuple[int, int]:
        m = map_message_to_group(plaintext, self.p)
        _, q, _, _ = public_key
        y = randint(1, q - 1)

        """
        Knowing both the ciphertext (c1, c2) and the plaintext, it is possible to
        recover the secret key x, since x = c2 * inverse_mod(m, p).

        Nonetheless, the ElGamal encryption scheme is secure under the
        fact that each encryption generates a new y and hence a new s.
        """

        return self._deterministic_part(m, y)

    def decrypt(
        self, private_key: ElGamalPrivateKey, ciphertext: Tuple[int, int]
    ) -> bytes:
        c1, c2 = ciphertext

        s = power_mod(c1, private_key, self.p)
        s_inv = inverse_mod(s, self.p)
        m = (c2 * s_inv) % self.p

        return unmap_message_from_group(m, self.p)

    def _deterministic_part(self, m: int, y: int) -> Tuple[int, int]:
        """
        Deterministic part of the encryption algorithm.
        """
        c1 = power_mod(self.g, y, self.p)
        s = power_mod(self.h, y, self.p)
        c2 = (m * s) % self.p

        return c1, c2

    def _generate_parameters(self) -> None:
        p, q = self._generate_primes()
        g = self._find_generator(p, q)

        self.p = p
        self.q = q
        self.g = g

        return

    def _generate_primes(self) -> Tuple[int, int]:
        q = random_prime(
            ZZ.random_element(2 ** (self.lambda_value - 1), 2**self.lambda_value),
            lbound=2,
        )
        lambda_value_bits = self.lambda_value.bit_length()
        p_min = 2 ** (self.lambda_value * lambda_value_bits)  # |p| >= lambda * |lambda|

        k = (p_min - 1) // q
        p = k * q + 1

        while not is_prime(p) or p < p_min:
            k += 1
            p = k * q + 1

        return p, q

    def _find_generator(self, p: int, q: int) -> int:
        """
        Find a generator for the multiplicative group of integers modulo p.

        The generator is a number g such that `g ^ ((p - 1) / q) mod p != 1`.
        """
        for a in range(2, p - 2):
            g = power_mod(a, (p - 1) // q, p)
            if g != 1:
                return g

def main() -> None:
    lambda_value: int = 128
    elgamal = ElGamalPKE(lambda_value)

    print(f"Generating keys with security parameter lambda = {lambda_value} bits")
    public_key, private_key = elgamal.generate_key_pair()
    print(f"Public key (p, q, g, h): {public_key}")
    print(f"Private key x: {private_key}")

    print()

    plaintext = b"Lorem ipsum dolor sit amet consectetur adipiscing elit"
    print(f"Plaintext: {plaintext}")

    print()

    ciphertext = elgamal.encrypt(public_key, plaintext)
    print(f"Ciphertext (c1, c2): {ciphertext}")

    print()

    print("Testing probabilistic encryption")
    ciphertext2 = elgamal.encrypt(public_key, plaintext)
    print(f"Ciphertext2 (c1, c2): {ciphertext2}")

    print(f"Probabilistic encryption: {ciphertext != ciphertext2}")

    print()

    decrypted = elgamal.decrypt(private_key, ciphertext)
    print(f"Deciphered plaintext: {decrypted}")

    print(f"Decryption successful: {plaintext == decrypted}")

    print()

    print("Testing tampering with the ciphertext")
    c1, c2 = ciphertext
    c1, c2 = c1, 2 * c2
    c = c1, c2

    elgamal.decrypt(private_key, c)
    print("Tampering detected: False")

    return

if __name__ == "__main__":
    main()
