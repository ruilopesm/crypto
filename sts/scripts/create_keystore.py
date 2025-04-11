import os
import argparse
from typing import Final

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    pkcs12,
    BestAvailableEncryption,
    NoEncryption,
)
from cryptography.x509 import load_pem_x509_certificate

CA_CERTIFICATE_PATH: Final[str] = "data/certificates/ca.crt"

def create_keystore(cert_path: str, key_path: str, password: str = None) -> None:
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()

    with open(key_path, "rb") as key_file:
        key_data = key_file.read()

    with open(CA_CERTIFICATE_PATH, "rb") as ca_file:
        ca_data = ca_file.read()

    certificate = load_pem_x509_certificate(cert_data)
    private_key = load_pem_private_key(key_data, password=password.encode("utf-8") if password else None)

    base_name = os.path.basename(cert_path)
    name_without_ext, _ = os.path.splitext(base_name)
    store_name = name_without_ext.encode("utf-8")

    encryption_algorithm = BestAvailableEncryption(password.encode("utf-8")) if password else NoEncryption()
    keystore_data = pkcs12.serialize_key_and_certificates(
        name=store_name,
        key=private_key,
        cert=certificate,
        cas=[load_pem_x509_certificate(ca_data)],
        encryption_algorithm=encryption_algorithm
    )

    with open(f"data/credentials/{name_without_ext}.p12", "wb") as outfile:
        outfile.write(keystore_data)

    print(f"Keystore created successfully at data/credentials/{name_without_ext}.p12")

def main():
    parser = argparse.ArgumentParser(description="Create a PKCS12 keystore from certificate and key")
    parser.add_argument("-c", "--cert", type=str, required=True, help="Path to the certificate file (PEM)")
    parser.add_argument("-k", "--key", type=str, required=True, help="Path to the private key file (PEM)")
    parser.add_argument("-p", "--password", type=str, required=False, help="Optional password for encrypting the keystore")
    args = parser.parse_args()

    create_keystore(args.cert, args.key, args.password)

if __name__ == "__main__":
    main()
