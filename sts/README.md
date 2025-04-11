## Station to Station

### Overview

This folder contains the code for the Station to Station (STS) protocol, which is a key exchange protocol that allows two parties to establish a shared secret key over an insecure channel. The STS protocol is based on the Diffie-Hellman key exchange, but also provides mutual authentication based on digital signatures and public key certificates.

Whilst developing this code, I decided to make use of the `cryptography` Python package for the cryptographic primitives. `X25519` was used for the Diffie-Hellman key exchange and `Ed25519` for the digital signatures. Nonetheless, you can find my implementation of the `Ed25519` signature algorithm in the [eddsa](../eddsa) folder.

Public key certificates are of the X.509 type, which is a well-known and established standard. I have also took the liberty to implement a simple certificate authority (CA) to issue these certificates, which was developed in the form of a Python script. The CA is not a full implementation of a real-world CA, but it serves the purpose of generating certificates for testing and demonstration purposes. It also allows one to not only verify common things like the expiration date of the certificate, but also to check if the certificate was, in fact, issued by the CA [^1] - which is, in this case, our trust anchor.

Besides the CA script, I have also created a simple script for creating a keystore based on the PKCS#12 standard, where one can store its private key and certificate. This keystore should be passed as a command line argument to the `sender.py` program (as we will shortly see).

Further communications between said two parties can be done using any symmetric encryption algorithm, but I have chosen to use `AES` in `GCM` mode for its efficiency and security (IND-CCA and INT-CTXT). Because this cipher uses keys of 128, 192 or 256 bits, it might be a good idea to use a key derivation function to derive a proper symmetric key from the shared secret. I have used `HKDF` for this purpose.

### Directory Structure

#### `common` folder

Here, you can find three files:

- `certificate_validator.py` which is responsible for validating a given certificate via the `CertificateValidator` class. It validates the certificate's signature and issuer, expiration date, subject as well as some critical extensions;
- `protocol.py` which contains a bunch of Python classes to represent the different messages that are exchanged during the STS protocol and in future messages;
- `utils.py` which contains some utility functions to help with the implementation of the protocol and working with PKCS#12 keystores.

#### `scripts` folder

This folder contains the scripts that were already mentioned: `generate_certificate.py` and `create_keystore.py`. Inside the `data` folder one can find generated certificates, keys and keystores for testing purposes.

#### Other files

- `receiver.py` which is the program representing the receiver (or server) side of the STS protocol;
- `sender.py` which is the program representing the sender (or client) side of the STS protocol.

### Running

First, make sure you have the required dependencies installed:

```bash
pip install -r requirements.txt
```

You can run the `generate_certificate.py` script to generate a self-signed certificate for the CA or simply rely on those that are already created:

```bash
python scripts/generate_certificate.py -t ca
```

Tip: simply run `python scripts/generate_certificate.py -h` to see all the options available. Same for the `create_keystore.py` script.

Then, you can run the `receiver.py` script to start the STS protocol, which will pick the keystore present at `data/credentials/receiver.p12` by default:

```bash
python receiver.py
```

In another terminal, run the `sender.py` script and let the magic happen:

```bash
python sender.py -creds data/credentials/rui.p12 # example path to keystore
```

After proper key exchange, the sender will be able to send encrypted messages of any length to the receiver. The receiver will be able to decrypt these messages, print them to the console and simply echo them back to the sender.

Example of a session between the sender and receiver, from the sender's perspective:

```bash
$ python sender.py -c data/credentials/rui.p12
Received PUB_SIGN_CERT from receiver
Received CONN_SUCCESS from receiver
You can now send messages

Enter message to send (or 'exit' to quit)
> Hey, how are you?
Message sent successfully

Enter message to send (or 'exit' to quit)
>
```

### References

- https://en.wikipedia.org/wiki/Station-to-Station_protocol
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
- https://cryptography.io/en/latest/x509/
- https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
- https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.hkdf.HKDF
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs12
- https://docs.python.org/3/library/asyncio.html

[^1]: Assuming our certificate chain is only two layers deep.
