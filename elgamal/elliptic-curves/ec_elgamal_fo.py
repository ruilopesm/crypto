import hashlib
from typing import List, Tuple

from sage.all import *

from ec_elgamal_pke import ECElGamalPKE
from utils import (
    CurvePoint,
    ECElGamalPrivateKey,
    ECElGamalPublicKey,
    from_bytes,
    map_message_to_curve,
    setup_ed25519,
    setup_p256,
    unmap_message_from_curve,
    xor,
)

class ECElGamalFO:
    """
    PKE IND-CCA scheme based on the ElGamal cryptosystem over elliptic curves.
    It was derived from the ECElGamalPKE class, using the Fujiski-Okamoto transformation.
    """
    def __init__(
        self, p: int, K, G: CurvePoint, n: int, curve, ell=8, lambda_value=128
    ):
        self.p = p
        self.K = K # Fp

        self.G = G
        self.n = n
        self.curve = curve

        self.ell = ell
        self.lambda_value = lambda_value

        # Base this class on the ECElGamalPKE class
        self._ec_elgamal_pke = ECElGamalPKE(p, K, G, n, curve, ell)

    def generate_key_pair(self) -> Tuple[ECElGamalPublicKey, ECElGamalPrivateKey]:
        return self._ec_elgamal_pke.generate_key_pair()

    def encrypt(
        self, public_key: ECElGamalPublicKey, message: bytes
    ) -> Tuple[bytes, Tuple[CurvePoint, CurvePoint]]:
        r = os.urandom(self.lambda_value // 8)

        gr = self._g(r, length=len(message))
        y = xor(message, gr)

        rr = self._h(r, y)
        kdet = Integer(rr % self.n)
        if kdet == 0:
            kdet = Integer(1)

        c = self._deterministic_part(r, kdet, public_key)

        return y, c

    def decrypt(
        self,
        public_key: ECElGamalPublicKey,
        private_key: ECElGamalPrivateKey,
        ciphertext: Tuple[CurvePoint, CurvePoint],
    ) -> bytes:
        y, c = ciphertext
        R, S = c

        r = unmap_message_from_curve(S - private_key * R, self.ell)

        rr = self._h(r, y)
        kdet = Integer(rr % self.n)
        if kdet == 0:
            kdet = Integer(1)

        R, S = self._deterministic_part(r, kdet, public_key)
        if c != (R, S):
            raise ValueError("Ciphertext has been tampered with")

        gr = self._g(r, len(y))

        return xor(y, gr)

    def _deterministic_part(
        self, m: bytes, k: int, public_key: ECElGamalPublicKey
    ) -> Tuple[CurvePoint, CurvePoint]:
        P = map_message_to_curve(m, self.p, self.ell, self.K, self.curve)
        R = k * self.G
        S = P + k * public_key

        return R, S

    def _h(self, *args: List[bytes]) -> int:
        b = b"".join(args)
        h = hashlib.sha256(b).digest()
        return from_bytes(h)

    def _g(self, r: bytes, length: int) -> bytes:
        """
        Generates an hash from a list of byte strings until
        the given `length` is met.
        """
        result = b""

        i = 0
        while len(result) < length:
            h = hashlib.sha256(r + str(i).encode()).digest()
            result += h
            i += 1

        return result[:length]

def main() -> None:
    print("Testing ElGamal IND-CCA secure over Elliptic Curves with Ed25519 Twisted Edwards Curve")
    p, K, G, n, curve = setup_ed25519()
    elgamal = ECElGamalFO(p, K, G, n, curve)

    print()

    print(f"Generating keys for ElGamal over Ed25519 curve")
    public_key, private_key = elgamal.generate_key_pair()
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

    print()

    print("Testing encryption and decryption")
    message = b"Hello, world!"
    print(f"Original message: {message}")
    ciphertext = elgamal.encrypt(public_key, message)
    print(f"Ciphertext: {ciphertext}")
    decrypted_message = elgamal.decrypt(public_key, private_key, ciphertext)
    print(f"Decrypted message: {decrypted_message}")

    print(f"Decryption successful: {message == decrypted_message}")

    print()

    print("Testing tampering with ciphertext")

    R, S = ciphertext[1]
    S = S + G
    ciphertext = (ciphertext[0], (R, S))

    try:
        elgamal.decrypt(public_key, private_key, ciphertext)
    except ValueError:
        print("Tampering detected: True")

    print("Testing ElGamal IND-CCA secure over Elliptic Curves with P-256 Curve")
    p, K, G, n, curve = setup_p256()
    elgamal = ECElGamalFO(p, K, G, n, curve)

    print()

    print(f"Generating keys for ElGamal over P-256 curve")
    public_key, private_key = elgamal.generate_key_pair()
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

    print()

    print("Testing encryption and decryption")
    message = b"Hello, world!"
    print(f"Original message: {message}")
    ciphertext = elgamal.encrypt(public_key, message)
    print(f"Ciphertext: {ciphertext}")
    decrypted_message = elgamal.decrypt(public_key, private_key, ciphertext)
    print(f"Decrypted message: {decrypted_message}")

    print(f"Decryption successful: {message == decrypted_message}")

    print()

    print("Testing tampering with ciphertext")

    R, S = ciphertext[1]
    S = S + G
    ciphertext = (ciphertext[0], (R, S))

    try:
        elgamal.decrypt(public_key, private_key, ciphertext)
    except ValueError:
        print("Tampering detected: True")

    return

if __name__ == "__main__":
    main()
