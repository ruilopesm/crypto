from cryptography.hazmat.primitives import padding

def pad_pcsk7(data: bytes, final: int) -> bytes:
    """
    Pad the given data using the PKCS7 padding scheme. The final parameter
    specifies the block size to use for padding, in bytes.
    """
    bits = final * 8
    padder = padding.PKCS7(bits).padder()
    return padder.update(data) + padder.finalize()

def unpad_pcks7(data: bytes, final: int) -> bytes:
    """
    Unpad the given data using the PKCS7 padding scheme. The final parameter
    specifies the block size to use for padding, in bytes.
    """
    bits = final * 8
    unpadder = padding.PKCS7(bits).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def xor(a: bytes, b: bytes) -> bytes:
    """
    Applies the XOR operation to two byte strings of equal length and returns
    the result.
    """
    return bytes(x ^ y for x, y in zip(a, b))
