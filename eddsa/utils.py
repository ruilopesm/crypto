from typing import Any, NoReturn, Union

type CurvePoint = Any

type EdDSAPublicKey = CurvePoint | bytes
type EdDSAPrivateKey = int

def set_bit(b: bytes, position: int, value: int) -> Union[bytes, NoReturn]:
    if value not in [0, 1]:
        raise ValueError("Value must be either 0 or 1")

    if position < 0 or position >= len(b) * 8:
        raise ValueError("Position out of range")

    byte_index = position // 8
    bit_index = position % 8

    byte = b[byte_index]
    mask = 1 << bit_index

    if value:
        byte |= mask
    else:
        byte &= ~mask

    return b[:byte_index] + bytes([byte]) + b[byte_index + 1 :]

def get_bit(b: bytes, position: int) -> int:
    if position < 0 or position >= len(b) * 8:
        raise ValueError("Position out of range")

    byte_index = position // 8
    bit_index = position % 8

    return (b[byte_index] >> bit_index) & 1

def from_bytes_little_endian(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little")

def to_bytes(n: int) -> bytes:
    n_bytes = byte_length(n)
    return n.to_bytes(n_bytes, byteorder="big")

def to_bytes_little_endian(n: int, length: int) -> bytes:
    return int(n).to_bytes(length, byteorder="little")

def byte_length(n: int) -> int:
    return (n.bit_length() + 7) // 8
