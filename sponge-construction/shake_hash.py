from ast import ClassDef
from typing import Final, Self

from cryptography.hazmat.primitives import hashes

SHAKE_PRIMITIVE: Final[ClassDef] = hashes.SHAKE256
SHAKE_RATE_IN_BITS: Final[int] = 1088
SHAKE_CAPACITY_IN_BITS: Final[int] = 512

class ShakeHash:
    """
    ShakeHash is a class that represents a hash function based on the SHA-3
    extendable output function (XOF) construction.

    Under the hood, the class uses the `cryptography` library to implement the
    SHA-3 hash function. Specifically, it uses the `Hash` class which is saved
    as a private field.
    """
    def __init__(self) -> Self:
        self.rate = SHAKE_RATE_IN_BITS // 8
        self.capacity = SHAKE_CAPACITY_IN_BITS // 8

        self._hash = self._new()

    def _new(self) -> None:
        primitive = SHAKE_PRIMITIVE(digest_size=self.rate + self.capacity)
        return hashes.Hash(primitive)

    def ensure_key_size(self, key: bytes) -> None:
        """
        Ensures that the given key has the correct size for the given hash.
        """
        if len(key) != self.capacity:
            raise ValueError(f"Key should be {self.capacity} bytes long")

    def update(self, data: bytes) -> None:
        """
        Apply a permutation function to the internal state with the given data.

        Permutation function can be seen as the `f` function in the sponge
        construction.
        """
        self._hash.update(data)

    def copy(self) -> Self:
        """
        Copy this hash instance, so that you may call `finalize` on it without
        affecting the original hash.
        """
        return self._hash.copy()

    def finalize(self) -> bytes:
        """
        Finalize the hash and return the digest.
        """
        return self._hash.finalize()

    def reset(self):
        """
        Reset the hash to its initial state.

        This is useful when you want to hash a new message with the same
        instance.
        """
        self._hash = self._new()
