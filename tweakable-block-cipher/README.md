## Tweakable Block Cipher

### Overview

This folder contains the code for a Tweakable Block Cipher (TBC) which operates in a Tweaked Authentication Encryption (TAE) mode.

The developed cipher is simply a block cipher where each block has a tweak associated with it. The tweak is a value composed by a nounce and some length-encoded information. These tweaks are useful for detecting repetitions or removals of blocks in the ciphertext. Having a nounce guarantees that even blocks that occupy the same position in other ciphertexts will be different and, therefore, cause a decryption failure.

It is interesting to note that by having a tweak we can also rely on using a cipher like `AES` in `ECB` mode for each block individually. This is, generally, not a recommended mode, but in this case it is all safe.

### Modules

- `ruped_tweakable.py` which contains the implementation of the TBC [^1];
- `utils.py` which contains some utility functions for XORing byte strings.

### Running

First, make sure you have the required dependencies installed:

```bash
pip install -r requirements.txt
```

Then, you can run the `main.py` script to test the TBC:

```bash
python main.py
```

Logs will be printed to the console, showing both the encryption and decryption process, as well as block removal detection.

### References

- https://people.eecs.berkeley.edu/~daw/papers/tweak-crypto02.pdf
- https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.ECB

[^1]: Named after me, Rui, and Pedro, a colleague of mine at the University of Minho. (Rui + Pedro = Ruped).
