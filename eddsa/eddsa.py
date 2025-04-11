"""
Test the EdDSA implementation for Ed25519 and Ed448 Twisted Edwards Curves.
"""

from ed25519 import Ed25519
from ed448 import Ed448

def main() -> None:
    print("Testing Ed25519")
    ed25519 = Ed25519()

    print(f"Curve equation: {ed25519.curve}")
    print(f"Base point G: {ed25519.G}")

    print()

    print(f"Generating keys for Ed25519")
    public_key, private_key = ed25519.generate_key_pair()
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

    print()

    message = b"Hello, world!"
    print(f"Signing message: {message}")
    signature = ed25519.sign((public_key, private_key), message)
    print(f"Signature: {signature}")

    print()

    print(f"Verifying signature")
    try:
        ed25519.verify(public_key, message, signature)
        print("Signature valid: True")
    except ValueError:
        print("Signature valid: False")

    print()

    print("Testing tampering with signature")
    signature = signature[:32] + b"\x00" * 32
    try:
        ed25519.verify(public_key, message, signature)
        print("Signature valid: True")
    except ValueError:
        print("Signature valid: False")

    print()

    print("Testing tampering with message")
    message1 = b"Hello, world!"
    signature = ed25519.sign((public_key, private_key), message1)
    message2 = b"Hello, world"
    try:
        ed25519.verify(public_key, message2, signature)
        print("Signature valid: True")
    except ValueError:
        print("Signature valid: False")

    print()

    print("Testing Ed448")
    ed448 = Ed448()

    print(f"Curve equation: {ed448.curve}")
    print(f"Base point G: {ed448.G}")

    print()

    print(f"Generating keys for Ed448")
    public_key, private_key = ed448.generate_key_pair()
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

    print()

    message = b"Hello, world!"
    context = b"Context"
    print(f"Signing message: {message}")
    signature = ed448.sign((public_key, private_key), message, context)
    print(f"Signature: {signature}")

    print()

    print(f"Verifying signature")
    try:
        ed448.verify(public_key, message, signature, context)
        print("Signature valid: True")
    except ValueError:
        print("Signature valid: False")

    print()

    print("Testing tampering with signature")
    signature = signature[:57] + b"\x00" * 57
    try:
        ed448.verify(public_key, message, signature, context)
        print("Signature valid: True")
    except ValueError:
        print("Signature valid: False")

    print()

    print("Testing tampering with message")
    message1 = b"Hello, world!"
    signature = ed448.sign((public_key, private_key), message1, context)
    message2 = b"Hello, world"
    try:
        ed448.verify(public_key, message2, signature, context)
        print("Signature valid: True")
    except ValueError:
        print("Signature valid: False")

    print()

    print("Testing tampering with context")
    context1 = b"Context"
    signature = ed448.sign((public_key, private_key), message, context1)
    context2 = b"context"
    try:
        ed448.verify(public_key, message, signature, context2)
        print("Signature valid: True")
    except ValueError:
        print("Signature valid: False")

    return


if __name__ == "__main__":
    main()
