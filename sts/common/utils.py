from cryptography.hazmat.primitives.serialization import pkcs12

def join_pair(x, y):
    """
    Produce a byte-string containing the tuple '(x,y)' ('x' and 'y' are byte-strings)
    """
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def get_userdata(p12_fname, password: str = None):
    with open(p12_fname, "rb") as f:
        p12 = f.read()

    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(
        p12, password.encode("utf-8") if password else None
    )
    return (private_key, user_cert, ca_cert)
