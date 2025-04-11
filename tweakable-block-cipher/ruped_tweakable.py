import os
from typing import Final, List, Tuple, Self

from utils import xor

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE_IN_BITS: Final[int] = 128
TWEAK_SIZE_IN_BITS: Final[int] = BLOCK_SIZE_IN_BITS // 2
KEY_SIZE_IN_BITS: Final[int] = BLOCK_SIZE_IN_BITS // 2

class RupedTweakable:
    def __init__(self, key: bytes) -> Self:
        self.key = key
        self.block_size = BLOCK_SIZE_IN_BITS // 8

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        ciphertext = b""

        blocks = self._blocks(plaintext)
        blocks, tau_size = self._pad(blocks)
        tau_bytes = tau_size.to_bytes(self.block_size, "big")

        halved_tweak_size = (TWEAK_SIZE_IN_BITS // 8) // 2
        length = len(blocks)
        nounce = os.urandom(halved_tweak_size)
        tweaks, auth_tweak = self._generate_tweaks(blocks, nounce)

        i = 0
        for block, tweak in zip(blocks, tweaks):
            key = tweak + self.key

            # Last block
            if i == length - 1:
                ciphered = self._cipher(key, tau_bytes)
                ciphertext += xor(ciphered, block)[:tau_size]
                break

            ciphered = self._cipher(key, block)
            ciphertext += ciphered

            i += 1

        tag = self._compute_tag(blocks, auth_tweak)

        return ciphertext, tag, nounce

    def decrypt(self, ciphertext: bytes, nounce: bytes) -> Tuple[bytes, bytes]:
        plaintext = b""

        blocks = self._blocks(ciphertext)
        blocks, tau_size = self._pad(blocks)
        tau_bytes = tau_size.to_bytes(self.block_size, "big")

        length = len(blocks)
        tweaks, auth_tweak = self._generate_tweaks(blocks, nounce)

        i = 0
        for block, tweak in zip(blocks, tweaks):
            key = tweak + self.key

            # Last block
            if i == length - 1:
                ciphered = self._cipher(key, tau_bytes)
                plaintext += xor(ciphered, block)[:tau_size]
                break

            deciphered = self._decipher(key, block)
            plaintext += deciphered

            i += 1

        blocks = self._blocks(plaintext)
        blocks, _ = self._pad(blocks)

        tag = self._compute_tag(blocks, auth_tweak)

        return plaintext, tag

    def _generate_tweaks(
        self, blocks: List[bytes], nounce: bytes
    ) -> Tuple[List[bytes], bytes]:
        """
        Generates the tweaks for the given list of blocks.

        Each tweak is composed of a nounce, a counter and a flag. The nounce
        should be given by the caller.

        Returns a tuple where the first component is a list of tweaks to be used
        for each block and the second component is the tweak to be used
        for authenticity purposes.
        """
        tweaks = []
        halved_tweak_size = (TWEAK_SIZE_IN_BITS // 8) // 2
        length = len(blocks)

        for i in range(length):
            tweak = (
                nounce
                + (i).to_bytes(halved_tweak_size - 1, "big")
                + (0).to_bytes(1, "big")
            )
            tweaks.append(tweak)

        # Auth tweak
        l = len(blocks).to_bytes(halved_tweak_size - 1, "big")
        auth_tweak = nounce + l + (1).to_bytes(1, "big")

        return tweaks, auth_tweak

    def _compute_tag(self, blocks: List[bytes], auth_tweak: bytes) -> bytes:
        """
        Computes the authentication tag by XORing all the blocks and encrypting
        the result with the established key and given tweak.

        Authentication tweak should be computed specifically by using
        `_generate_tweaks` method.
        """
        key = auth_tweak + self.key

        auth = (0).to_bytes(self.block_size, "big")
        for block in blocks:
            auth = xor(auth, block)

        return self._cipher(key, auth)

    def _blocks(self, data: bytes) -> List[bytes]:
        result = []

        for i in range(0, len(data), self.block_size):
            result.append(data[i : i + self.block_size])

        return result

    def _pad(self, blocks: List[bytes]) -> Tuple[List[bytes], bytes]:
        """
        Pads the list of blocks with left 0s.

        Returns the padded blocks and 'tau', which is the length of the last block.
        """
        last = blocks[-1]
        length = len(last)

        pad = self.block_size - length
        blocks[-1] += b"\x00" * pad

        return blocks, length

    def _unpad(self, data: bytes) -> bytes:
        """
        Removes the padding from the list of blocks.

        Assumes data was passed through `_pad` method.
        """
        return data.rstrip(b"\x00")

    def _cipher(self, key: bytes, data: bytes) -> bytes:
        meta = self._build_ecb(key)
        encryptor = meta.encryptor()

        return encryptor.update(data) + encryptor.finalize()

    def _decipher(self, key: bytes, data: bytes) -> bytes:
        meta = self._build_ecb(key)
        decryptor = meta.decryptor()

        return decryptor.update(data) + decryptor.finalize()

    def _build_ecb(self, key: bytes) -> Cipher:
        algorithm = algorithms.AES(key)
        return Cipher(algorithm, modes.ECB(), backend=default_backend())
