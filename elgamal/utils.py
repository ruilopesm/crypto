from typing import NoReturn, Tuple, Union

type ElGamalPublicKey = Tuple[int, int, int, int]
type ElGamalPrivateKey = int

def map_message_to_group(message: bytes, p: int) -> Union[int, NoReturn]:
    m = from_bytes(message)

    if m >= p:
        raise ValueError("Message is too large for the given group.")

    return m

def unmap_message_from_group(m: int, p: int) -> bytes:
    n_bytes = byte_length(p)
    message = m.to_bytes(n_bytes, byteorder="big")
    return message.lstrip(b"\x00")

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def to_bytes(n: int) -> bytes:
    n_bytes = byte_length(n)
    return n.to_bytes(n_bytes, byteorder="big")

def from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def byte_length(n: int) -> int:
    return (n.bit_length() + 7) // 8
