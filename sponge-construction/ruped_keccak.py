import os
from typing import Self, Tuple

from shake_hash import ShakeHash
from utils import pad_pcsk7, unpad_pcks7, xor

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class RupedKeccak:
    """
    RupedKeccak is a class that represents an authenticated encryption with
    associated data (AEAD) scheme based on the Keccak hash functions (provided via
    the `ShakeHash` class) and a sponge function construction.

    It expects an initialization vector (IV), a key, and an `ShakeHash` object to be
    provided.
    """
    def __init__(self, iv: bytes, key: bytes, xof: ShakeHash) -> Self:
        self.iv = iv
        self.xof = xof

        self.xof.ensure_key_size(key)
        self.key = key

        self.rate = self.xof.rate
        self.capacity = self.xof.capacity
        self.shake = None

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """
        Encryption function that takes a plaintext and associated data and
        returns a ciphertext and a tag.
        """
        nonce = self._derive(os.urandom(16))
        self.xof.reset()

        initial = self.iv + self.key
        self.xof.update(initial)
        self.xof.update(nonce)

        ciphertext, tag = self._process(plaintext, associated_data, encrypt=True)
        return nonce + ciphertext, tag

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """
        Decryption function that takes a ciphertext and associated data and
        returns a plaintext and a tag.
        """
        try:
            nonce, ciphertext = ciphertext[:16], ciphertext[16:]
            self.xof.reset()

            initial = self.iv + self.key
            self.xof.update(initial)
            self.xof.update(nonce)

            return self._process(ciphertext, associated_data, encrypt=False)
        except ValueError:
            print(f"Error while decrypting")
            return bytes(), bytes()

    def _process(self, data: bytes, associated_data: bytes, encrypt: bool) -> Tuple[bytes, bytes]:
        result = b""

        # Absorb phase (with associated data)
        associated_data = pad_pcsk7(associated_data, self.xof.rate)

        for i in range(0, len(associated_data), self.xof.rate):
            state = self.xof.copy().finalize()
            block = associated_data[i : i + self.xof.rate]

            (above, below) = self._divide(state, self.xof.rate)
            current = xor(block, above) + below
            self.xof.update(current)

        # Squeeze phase (with data)
        if encrypt:
            data = pad_pcsk7(data, self.xof.rate)

        for i in range(0, len(data) - self.xof.rate, self.xof.rate):
            state = self.xof.copy().finalize()
            block = data[i : i + self.xof.rate]

            (above, below) = self._divide(state, self.xof.rate)
            processed = xor(block, above)
            result += processed

            first = processed if encrypt else block
            self.xof.update(first + below)

        # Last block is treated differently,
        # since the below part should be XORed with the key
        state = self.xof.copy().finalize()
        last = data[-self.xof.rate :]

        (above, below) = self._divide(state, self.xof.rate)
        processed = xor(last, above)
        result += processed
        below = xor(self.key, below)

        first = processed if encrypt else last
        self.xof.update(first + below)

        # Generate tag
        state = self.xof.copy().finalize()
        tag = xor(self.key, state[self.xof.rate :])

        if not encrypt:
            result = unpad_pcks7(result, self.xof.rate)

        return result, tag

    def _divide(self, data: bytes, rate: int) -> Tuple[bytes, bytes]:
        return data[:rate], data[rate:]

    def _derive(self, seed: bytes) -> bytes:
        key = HKDF(algorithm=hashes.SHA512(), length=16, salt=b"salt", info=None)
        return key.derive(seed)
