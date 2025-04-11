from typing import Any, Tuple

import hashlib

from typing import List

from sage.all import *

type CurvePoint = Any

type ECElGamalPublicKey = CurvePoint | bytes
type ECElGamalPrivateKey = int

def setup_ed25519() -> Tuple[int, Any, CurvePoint, int, Any]:
    p = 2**255 - 19
    K = GF(p)
    a = -1
    d = -K(121665) / K(121666)

    ka = K(a)
    kd = K(d)
    A = 2 * (ka + kd) / (ka - kd)
    B = 4 / (ka - kd)
    alfa = A / (3 * B)
    s = B
    a4 = s ** (-2) - 3 * alfa**2
    a6 = -(alfa**3) - a4 * alfa

    curve = EllipticCurve(K, [a4, a6])

    G = (
        K(15112221349535400772501151409588531511454012693041857206046113283949847762202),
        K(46316835694926478169428394003475163141307993866256225615783033603165251855960),
    )

    if G == (0, 1):
        return p, K, curve(0), curve

    x, y = G
    z = (1 + y) / (1 - y)
    w = z / x
    G = curve(z / s + alfa, w / s)

    n = 2**252 + 27742317777372353535851937790883648493

    return p, K, G, n, curve

def setup_p256() -> Tuple[int, Any, CurvePoint, int, Any]:
    p = int(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
    K = GF(p)
    a = int(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
    b = int(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)

    ka = K(a)
    kb = K(b)
    curve = EllipticCurve(K, [ka, kb])

    G = (
        K(int(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)), 
        K(int(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)),
    )
    G = curve(G)

    n = int(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)

    return p, K, G, n, curve

def map_message_to_curve(m: bytes, p: int, ell: int, K: Any, curve: Any) -> CurvePoint:
    """
    Encodes a fixed-length message into a point on the curve using the Koblitz method.

    1. Convert message to integer m.
    2. Verify m fits in (k-1-ell) bits (where k is bit-length of p).
    3. Compute x0 = m << ell.
    4. For i in 0 to 2^ell - 1, let x = x0 + i:
        - Compute f(x) = x^3 + a*x + b mod p.
        - If f(x) is a quadratic residue, let y = sqrt(f(x)) and return the point (x, y).
    5. If no candidate works, raise an error.
    """
    m = from_bytes(m)
    kbits = p.bit_length()
    if m.bit_length() > (kbits - 1 - ell):
        raise ValueError("Message too long to encode in a single block")

    x0 = m << ell

    for i in range(2**ell):
        x = x0 + i
        if x >= p:
            break

        # Compute f(x) = x^3 + a*x + b mod p
        f = K(x**3 + curve.a4() * x + curve.a6()) % p
        if f.is_square():
            y = f.sqrt()
            return curve([x, y])

    raise ValueError("Non-encodable message: tried 2^ell possibilities")

def unmap_message_from_curve(P: CurvePoint, ell: int) -> bytes:
    x = Integer(P[0])
    m = x >> ell
    return to_bytes(m)

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def to_bytes(n: int) -> bytes:
    n_bytes = byte_length(n)
    return n.to_bytes(n_bytes, byteorder="big")

def byte_length(n: int) -> int:
    return (n.bit_length() + 7) // 8

def H(*args: List[bytes], length: int) -> int:
    b = b"".join(args)
    h = hashlib.sha256(b).digest()
    return from_bytes(h) % (length)
