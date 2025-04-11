## Sponge Construction

### Overview

This folder contains the code for an Authenticated with Associated Data (AEAD) cipher based on the sponge construction of the SHA-3 or SHAKE hash function, developed by the Keccak team. These kind of hash functions follow a construction that allows for the generation of a variable-length output and can also be known as XOFs (eXtendable Output Functions).

The developed cipher is, by design, resistant to ciphertext and associated data tampering attacks.

Other primitives like `HKDF`, from the `cryptography` Python package, were also used to derive keys from a supposedly shared secret.

Be aware that is is a symmetric cipher and should rely on the fact that the sender and receiver (on a real world scenario) should, somehow, share a secret. This is not the case in the current implementation, which only focus on the AEAD cipher.

You can check the [STS](../sts/) folder for an implementation of a Station to Station protocol that allows for the accomplishment of a key exchange between two parties in a secure way.

### Modules

- `ruped_keccak.py` which contains the implementation of the AEAD cipher [^1];
- `shake_hash` which contains a wrapper class around the `SHAKE256` class from `cryptography` Python package;
- `utils.py` which contains some utility functions for working with padding and XORing byte strings.

### Running

First, make sure you have the required dependencies installed:

```bash
pip install -r requirements.txt
```

Then, you can run the `main.py` script to test the AEAD cipher:

```bash
python main.py
```

Logs will be printed to the console, showing both the encryption and decryption process, as well as tampering detection.

### References

- https://keccak.team/sponge_duplex.html
- https://ascon.isec.tugraz.at/
- https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/#cryptography.hazmat.primitives.hashes.XOFHash
- https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.hkdf.HKDF

[^1]: Named after me, Rui, and Pedro, a colleague of mine at the University of Minho. (Rui + Pedro = Ruped). Keccack speaks for itself :D
