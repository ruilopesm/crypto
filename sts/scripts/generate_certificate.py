import argparse
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509 import NameOID

def generate_ca_certificate() -> None:
    key = ed25519.Ed25519PrivateKey.generate()

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Braga"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "STS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Certificate Authority of STS"),
            x509.NameAttribute(NameOID.PSEUDONYM, "CA"),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    builder = builder.not_valid_before(datetime.now(timezone.utc))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    certificate = builder.sign(key, algorithm=None)
    with open("data/certificates/ca.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    with open("data/keys/ca.key", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print("CA certificate successfully generated and saved to data/certificates/ca.crt")
    print("CA private key successfully generated and saved to data/keys/ca.key")

def generate_party_certificate(ca_certificate: str, ca_private_key: str, party: str) -> None:
    with open(ca_certificate, "rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read())

    with open(ca_private_key, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    key = ed25519.Ed25519PrivateKey.generate()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Braga"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "STS"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "STS - Session"),
            x509.NameAttribute(NameOID.COMMON_NAME, party),
            x509.NameAttribute(NameOID.PSEUDONYM, party),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_certificate.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    builder = builder.not_valid_before(datetime.now(timezone.utc))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    certificate = builder.sign(ca_private_key, algorithm=None)
    with open(f"data/certificates/{party}.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    with open(f"data/keys/{party}.key", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(f"{party} certificate successfully generated and saved to data/certificates/{party}.crt")
    print(f"{party} private key successfully generated and saved to data/keys/{party}.key")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--type",
        required=True,
        help="Type of certificate",
        choices=["ca", "party"],
    )
    parser.add_argument(
        "-ca",
        "--ca",
        required=False,
        help="If type is receiver, path to CA certificate",
    )
    parser.add_argument(
        "-k",
        "--key",
        required=False,
        help="If type is party, path to CA private key",
    )
    parser.add_argument(
        "-p",
        "--party",
        required=False,
        help="If type is party, name of the party",
    )

    args = parser.parse_args()
    if args.type == "party" and (not args.ca or not args.key):
        print("CA certificate and private key are required for party certificate generation")
        return
    if args.type == "party" and not args.party:
        print("Party name is required for party certificate generation")
        return

    match args.type:
        case "ca":
            generate_ca_certificate()
        case "party":
            generate_party_certificate(args.ca, args.key, args.party)
        case _:
            print(f"Generator for {args.type} not implemented yet")

if __name__ == "__main__":
    main()
