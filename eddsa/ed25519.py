import hashlib
from typing import Any, Final, NoReturn, Tuple, Union

from sage.all import *

from utils import (
    CurvePoint,
    EdDSAPrivateKey,
    EdDSAPublicKey,
    from_bytes_little_endian,
    get_bit,
    set_bit,
    to_bytes,
    to_bytes_little_endian,
)

class Ed25519:
    """
    Digital Signature Algorithm scheme based on the Ed25519 Twisted Edwards Curve.
    """
    def __init__(self):
        self.c: Final[int] = 3
        self.b: Final[int] = 256
        self.p: Final[int] = 2**255 - 19

        self.K = GF(self.p)
        self.a: Final[int] = -1
        self.d = -self.K(121665) / self.K(121666)

        self._to_weierstrass()
        self.l: Final[int] = 2**252 + 27742317777372353535851937790883648493

        G = (
            self.K(
                15112221349535400772501151409588531511454012693041857206046113283949847762202
            ),
            self.K(
                46316835694926478169428394003475163141307993866256225615783033603165251855960
            ),
        )
        self.G: Final[CurvePoint] = self._to_weierstrass_point(G)

    def generate_key_pair(self) -> Tuple[EdDSAPublicKey, EdDSAPrivateKey]:
        private_key = ZZ.random_element(2 ** (self.b - 1), 2**self.b)

        h = self._hash(to_bytes(private_key))

        first_half = h[:32]
        s = self._calculate_s(first_half)
        sg = s * self.G

        Q = self._encode(sg)
        public_key = Q

        return public_key, private_key

    def sign(self, keys: Tuple[EdDSAPublicKey, EdDSAPrivateKey], m: bytes) -> bytes:
        public_key, private_key = keys

        h = self._hash(to_bytes(private_key))

        first_half = h[:32]
        s = self._calculate_s(first_half)
        second_half = h[32:]

        r = self._hash(second_half + m)
        r = from_bytes_little_endian(r)

        R = r * self.G
        R = self._encode(R)

        rqm = self._hash(R + public_key + m)
        rqm = from_bytes_little_endian(rqm)
        S = (r + rqm * s) % self.l
        S = to_bytes_little_endian(S, 32)

        return R + S

    def verify(
        self, public_key: EdDSAPublicKey, m: bytes, signature: bytes
    ) -> Union[bool, NoReturn]:
        Rs = signature[:32]
        Ss = signature[32:]

        s = from_bytes_little_endian(Ss)
        if s >= 0 and s < self.l:
            Q = self._decode(public_key)
            R = self._decode(Rs)

            if R is None or Q is None:
                self._raise_invalid_signature()
        else:
            self._raise_invalid_signature()

        hash_data = Rs + public_key + m
        digest = self._hash(hash_data)
        t = from_bytes_little_endian(digest)

        """
        2^c * s[G] = 2^c * R + 2^c * t[Q]
        """
        power = 2**self.c
        if (power * s) * self.G == (power * R) + (power * t) * Q:
            return True
        else:
            self._raise_invalid_signature()

    def _to_weierstrass(self):
        ka = self.K(self.a)
        kd = self.K(self.d)

        A = 2 * (ka + kd) / (ka - kd)
        B = 4 / (ka - kd)

        alfa = A / (3 * B)
        self.alfa = alfa

        s = B
        self.s = s

        a4 = s ** (-2) - 3 * alfa**2
        a6 = -(alfa**3) - a4 * alfa

        self.curve = EllipticCurve(self.K, [a4, a6])

    def _to_weierstrass_point(self, P: Tuple[int, int]) -> CurvePoint:
        if P == (0, 1):
            return self.curve(0)

        x, y = P
        z = (1 + y) / (1 - y)
        w = z / x

        return self.curve(z / self.s + self.alfa, w / self.s)

    def _from_weierstrass_point(self, Q: CurvePoint) -> Tuple[int, int]:
        a, b = Q.xy()
        z = self.s * (a - self.alfa)

        y = (z - 1) / (z + 1)
        x = (a - self.alfa) / b

        return x, y

    def _calculate_s(self, digest: bytes) -> int:
        digest = set_bit(digest, 0, 0)
        digest = set_bit(digest, 1, 0)
        digest = set_bit(digest, 2, 0)
        digest = set_bit(digest, 254, 1)
        digest = set_bit(digest, 255, 0)

        s = from_bytes_little_endian(digest)
        return s

    def _encode(self, Q: CurvePoint) -> bytes:
        length = self.b

        x, y = self._from_weierstrass_point(Q)

        s = to_bytes_little_endian(y, length // 8)
        if mod(x, 2) != 0:
            s = set_bit(s, length - 1, 1)

        return s

    def _decode(self, s: bytes) -> CurvePoint:
        length = self.b
        if len(s) != length // 8:
            return None

        xs = get_bit(s, length - 1)
        s = set_bit(s, length - 1, 0)

        y = from_bytes_little_endian(s)
        if y is None:
            return None

        y = self.K(y)

        x_squared = (y * y - 1) / (self.d * y * y + 1)
        x = self._sqrt(x_squared)
        if x is None:
            return None

        if mod(x, 2) != xs:
            x = -x

        z = (self.K(1) + y) / (self.K(1) - y)
        a = self.alfa + z / self.s
        b = z / (self.s * x)

        return self.curve(a, b)

    # Assuming p = 5 mod 8
    def _sqrt(self, x: int) -> Any:
        def sqrt8k5(x) -> Any:
            y = power_mod(x, (self.p + 3) // 8, self.p)
            if (y * y) % self.p == x % self.p:
                return y
            else:
                z = power_mod(2, (self.p - 1) // 4, self.p)
                return (y * z) % self.p

        y = sqrt8k5(x)
        ky = self.K(y)

        return ky if ky * ky == x else None

    def _hash(self, m: bytes) -> bytes:
        return hashlib.sha512(m).digest()

    def _raise_invalid_signature(self) -> NoReturn:
        raise ValueError("Invalid signature")
