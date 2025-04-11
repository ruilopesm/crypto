from typing import Tuple

from sage.all import *

from utils import (
    CurvePoint,
    ECElGamalPrivateKey,
    ECElGamalPublicKey,
    map_message_to_curve,
    setup_ed25519,
    setup_p256,
    unmap_message_from_curve,
)

class ECElGamalPKE:
    """
    PKE IND-CPA scheme based on the ElGamal cryptosystem over elliptic curves.
    """
    def __init__(self, p: int, K, G: CurvePoint, n: int, curve, ell=8):
        self.p = p
        self.K = K # Fp

        self.G = G
        self.n = n
        self.curve = curve

        self.ell = ell

    def generate_key_pair(self) -> Tuple[ECElGamalPublicKey, ECElGamalPrivateKey]:
        private_key = ZZ.random_element(1, self.n)
        public_key = private_key * self.G

        return public_key, private_key

    def encrypt(
        self, public_key: ECElGamalPublicKey, message: bytes
    ) -> Tuple[CurvePoint, CurvePoint]:
        P = map_message_to_curve(message, self.p, self.ell, self.K, self.curve)
        k = ZZ.random_element(1, self.n)
        R = k * self.G
        S = P + k * public_key

        return R, S

    def decrypt(
        self,
        private_key: ECElGamalPrivateKey,
        ciphertext: Tuple[CurvePoint, CurvePoint],
    ) -> bytes:
        R, S = ciphertext
        P = S - private_key * R

        return unmap_message_from_curve(P, self.ell)

def main() -> None:
    print("Testing ElGamal over Elliptic Curves with Ed25519 Twisted Edwards Curve")
    p, K, G, n, curve = setup_ed25519()
    elgamal = ECElGamalPKE(p, K, G, n, curve)

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
    decrypted_message = elgamal.decrypt(private_key, ciphertext)
    print(f"Decrypted message: {decrypted_message}")

    print()

    print(f"Decryption successful: {message == decrypted_message}")

    print()

    print("Testing ElGamal over Elliptic Curves with P-256 Curve")
    p, K, G, n, curve = setup_p256()
    elgamal = ECElGamalPKE(p, K, G, n, curve)

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
    decrypted_message = elgamal.decrypt(private_key, ciphertext)
    print(f"Decrypted message: {decrypted_message}")

    print()

    print(f"Decryption successful: {message == decrypted_message}")

    return

if __name__ == "__main__":
    main()
