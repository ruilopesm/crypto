from datetime import datetime, timezone
from typing import Final

from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.x509.extensions import BasicConstraints, KeyUsage

CA_CERTIFICATE_PATH: Final[str] = "data/certificates/ca.crt"

class CertificateValidator:
    def __init__(self):
        try:
            with open(CA_CERTIFICATE_PATH, "rb") as cert_file:
                certificate_data = cert_file.read()

            self.ca_cert = x509.load_pem_x509_certificate(certificate_data)
        except (ValueError, FileNotFoundError):
            print(f"Error loading trusted certificate: {self.ca_cert}")

    def validate_certificate(self, certificate: Certificate, expected_identity: str):
        """
        Validates a x509 certificate

        Steps:
        - Verifies the certificate's signature using a trusted CA certificate
        - Validates the certificate's validity period
        - Verifies the certificate's subject identity against the expected identity
        - Validates the values of critical extensions
        """
        if (
            self.verify_signature(certificate)
            and self.validate_validity(certificate)
            and self.verify_identity(certificate, expected_identity)
            and self.validate_critical_extensions(certificate)
        ):
            return True

        return False

    def verify_signature(self, certificate: Certificate):
        issuer = certificate.issuer

        if issuer == self.ca_cert.subject:
            try:
                self.ca_cert.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes)
                return True
            except Exception:
                print("Invalid signature for certificate issued by", issuer)
                return False

        return False

    def validate_validity(self, certificate: Certificate):
        now = datetime.now().astimezone(timezone.utc)

        if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
            print("Certificate date is not valid")
            return False

        return True

    def verify_identity(self, certificate: Certificate, expected_identity: str):
        pseudonym = certificate.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[0].value

        if pseudonym != expected_identity:
            print(f"Certificate subject does not match expected identity: {expected_identity}")
            print(f"Actual subject: {pseudonym}")
            return False

        return True

    def validate_critical_extensions(self, certificate):
        for extension in certificate.extensions:
            if extension.critical:
                if isinstance(extension.value, BasicConstraints):
                    if extension.value.ca:
                        print("Certificate marked as CA but is not a CA certificate")
                        return False
                
                elif isinstance(extension.value, KeyUsage):
                    if not extension.value.digital_signature:
                        print("KeyUsage extension does not allow digital signature")
                        return False
                
                else:
                    print(f"Unhandled critical extension type: {extension.value}")
                    return False

        return True
