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

class Ed448:
    """
    Digital Signature Algorithm scheme based on the Ed448 Twisted Edwards Curve.

    This curve is more secure than Ed25519, offering a security level of 224 bits.
    """
    def __init__(self):
        self.c: Final[int] = 2
        self.b: Final[int] = 456
        self.p: Final[int] = 2**448 - 2**224 - 1

        self.K = GF(self.p)
        self.a: Final[int] = 1
        self.d = self.K(-39081)

        self._to_weierstrass()
        self.l: Final[int] = (
            2**446
            - 13818066809895115352007386748515426880336692474882178609894547503885
        )

        G = (
            self.K(
                224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710
            ),
            self.K(
                298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
            ),
        )
        self.G: Final[CurvePoint] = self._to_weierstrass_point(G)

    def generate_key_pair(self) -> Tuple[EdDSAPublicKey, EdDSAPrivateKey]:
        private_key = ZZ.random_element(2 ** (self.b - 1), 2**self.b)

        h = self._hash(to_bytes(private_key), 114)

        first_half = h[:57]
        s = self._calculate_s(first_half)
        sg = s * self.G

        Q = self._encode(sg)
        public_key = Q

        return public_key, private_key

    def sign(
        self, keys: Tuple[EdDSAPublicKey, EdDSAPrivateKey], m: bytes, context: bytes
    ) -> bytes:
        public_key, private_key = keys

        h = self._hash(to_bytes(private_key), 114)

        first_half = h[:57]
        s = self._calculate_s(first_half)
        second_half = h[57:]

        dom4 = self._dom4(0, context)
        r = self._hash(dom4 + second_half + m, 114)
        r = from_bytes_little_endian(r)

        R = r * self.G
        R = self._encode(R)

        drqm = self._hash(dom4 + R + public_key + m, 114)
        drqm = from_bytes_little_endian(drqm)
        S = (r + drqm * s) % self.l
        S = to_bytes_little_endian(S, 57)

        return R + S

    def verify(
        self, public_key: EdDSAPublicKey, m: bytes, signature: bytes, context: bytes
    ) -> Union[bool, NoReturn]:
        Rs = signature[:57]
        Ss = signature[57:]

        s = from_bytes_little_endian(Ss)
        if s >= 0 and s < self.l:
            Q = self._decode(public_key)
            R = self._decode(Rs)

            if R is None or Q is None:
                self._raise_invalid_signature()
        else:
            self._raise_invalid_signature()

        hash_data = Rs + public_key + m
        dom4 = self._dom4(0, context)
        digest = self._hash(dom4 + hash_data, 114)
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
        digest = set_bit(digest, 448, 0)
        digest = set_bit(digest, 449, 0)
        digest = set_bit(digest, 450, 0)
        digest = set_bit(digest, 451, 0)
        digest = set_bit(digest, 452, 0)
        digest = set_bit(digest, 453, 0)
        digest = set_bit(digest, 454, 0)
        digest = set_bit(digest, 455, 0)
        digest = set_bit(digest, 439, 1)

        s = from_bytes_little_endian(digest)
        return s

    def _dom4(self, f: int, c: bytes) -> bytes:
        return b"SigEd448" + bytes([f]) + bytes([len(c)]) + c

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

        x_squared = (self.K(1) - y * y) / (self.K(1) - self.d * y * y)
        x = self._sqrt(x_squared)
        if x is None:
            return None

        if mod(x, 2) != xs:
            x = -x

        z = (self.K(1) + y) / (self.K(1) - y)
        a = self.alfa + z / self.s
        b = z / (self.s * x)

        return self.curve(a, b)

    # Assuming p = 3 mod 4
    def _sqrt(self, x: int) -> Any:
        def sqrt4k3(x) -> Any:
            return power_mod(x, (self.p + 1) // 4, self.p)

        y = sqrt4k3(x)
        ky = self.K(y)

        return ky if ky * ky == x else None

    def _hash(self, m: bytes, length: int) -> bytes:
        return hashlib.shake_256(m).digest(length)

    def _raise_invalid_signature(self) -> NoReturn:
        raise ValueError("Invalid signature")
