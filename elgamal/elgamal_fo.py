import hashlib
from random import randint
from typing import List, NoReturn, Tuple, Union

from sage.all import *

from elgamal_pke import ElGamalPKE
from utils import (
    ElGamalPrivateKey,
    ElGamalPublicKey,
    from_bytes,
    map_message_to_group,
    to_bytes,
    xor,
)

class ElGamalFO:
    """
    PKE IND-CCA scheme based on the ElGamal cryptosystem. It was derived from
    the ElGamalPKE class, using the Fujisaki-Okamoto transformation.

    This is a form of authenticated encryption, meaning that the decryption
    algorithm will fail if the ciphertext has been tampered with.
    """
    def __init__(self, lambda_value: int):
        self.lambda_value = lambda_value

        # Base this class on the ElGamalPKE class
        self._elgamal_pke = ElGamalPKE(lambda_value)
        self.p = self._elgamal_pke.p
        self.q = self._elgamal_pke.q
        self.g = self._elgamal_pke.g

    def generate_key_pair(self) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
        public_key, private_key = self._elgamal_pke.generate_key_pair()
        _, _, _, h = public_key
        self.h = h

        return public_key, private_key

    def encrypt(
        self, public_key: ElGamalPublicKey, plaintext: bytes
    ) -> Tuple[int, Tuple[int, int]]:
        m = map_message_to_group(plaintext, self.p)
        _, q, _, _ = public_key
        r = randint(1, q - 1)

        gr = self._g(to_bytes(r), length=len(plaintext))
        y = xor(to_bytes(m), gr)

        rr = self._h(to_bytes(r), y)
        c1, c2 = self._deterministic_part(r, from_bytes(rr))

        y = from_bytes(y)
        c = c1, c2

        return y, c

    def decrypt(
        self, private_key: ElGamalPrivateKey, ciphertext: Tuple[int, Tuple[int, int]]
    ) -> Union[bytes, NoReturn]:
        y, c = ciphertext
        y = to_bytes(y)

        r = self._elgamal_pke.decrypt(private_key, c)

        rr = self._h(r, y)
        c1, c2 = self._deterministic_part(from_bytes(r), from_bytes(rr))

        if c != (c1, c2):
            raise ValueError("Ciphertext has been tampered with")

        gr = self._g(to_bytes(from_bytes(r)), length=len(y))

        return xor(y, gr)

    def _deterministic_part(self, r: int, rr: int, h=None) -> Tuple[int, int]:
        c1 = power_mod(self.g, rr, self.p)

        if h is not None:
            s = power_mod(h, rr, self.p)
        else:
            s = power_mod(self.h, rr, self.p)

        c2 = (r * s) % self.p

        return c1, c2

    def _h(self, *args: List[bytes]) -> bytes:
        """
        Generates an hash from a byte string with lambda size.
        """
        b = b"".join(args)
        h = hashlib.sha256(b).digest()
        return h[: self.lambda_value]

    def _g(self, *args: List[bytes], length: int) -> bytes:
        """
        Generates an hash from a list of byte strings until
        the given `length` is met.
        """
        result = b""
        b = b"".join(args)

        i = 0
        while len(result) < length:
            h = hashlib.sha256(b + str(i).encode()).digest()
            result += h
            i += 1

        return result[:length]

def main() -> None:
    lambda_value: int = 128
    elgamal_fo = ElGamalFO(lambda_value)

    print(f"Generating keys with security parameter lambda = {lambda_value} bits")
    public_key, private_key = elgamal_fo.generate_key_pair()
    print(f"Public key (p, q, g, h): {public_key}")
    print(f"Private key x: {private_key}")

    print()

    plaintext = b"Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor"
    print(f"Plaintext: {plaintext}")

    print()

    ciphertext = elgamal_fo.encrypt(public_key, plaintext)
    print(f"Ciphertext (y, c1, c2): {ciphertext}")

    print()

    decrypted = elgamal_fo.decrypt(private_key, ciphertext)
    print(f"Deciphered plaintext: {decrypted}")

    print(f"Decryption successful: {plaintext == decrypted}")

    print()

    print("Testing tampering with the ciphertext")
    y, c = ciphertext
    c1, c2 = c

    p = public_key[0]
    _c1 = (c1 + 1) % p
    c = (_c1, c2)

    try:
        decrypted = elgamal_fo.decrypt(private_key, (y, c))
    except ValueError:
        print("Tampering detected: True")

    return

if __name__ == "__main__":
    main()
