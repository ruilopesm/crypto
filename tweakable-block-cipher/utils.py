def xor(a: bytes, b: bytes) -> bytes:
    """
    Applies the XOR operation to two byte strings of equal length and returns
    the result.
    """
    return bytes(x ^ y for x, y in zip(a, b))
