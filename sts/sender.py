import argparse
import asyncio
import os
import base64 as b64

from common.protocol import *
from common.cerificate_validator import CertificateValidator
from common import utils

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.exceptions import InvalidSignature

PORT = 8889
MAX_MESSAGE_SIZE = 8192

class Sender:
    def __init__(self, creds: str):
        self.dh_private_key = X25519PrivateKey.generate()
        self.receiver_dh_pub_key: X25519PublicKey = None
        self.receiver_certificate: Certificate = None
        self.receiver_certificate_name: str = None
        
        self.ed25519_private_key, self.certificate, self.ca_certificate = utils.get_userdata(creds)

        base_name = os.path.basename(creds)
        name_without_ext, _ = os.path.splitext(base_name)
        self.certificate_name = name_without_ext

        self.certificate_validator = CertificateValidator()
        if not self.certificate_validator.validate_certificate(self.certificate, self.certificate_name):
            raise ValueError("Invalid certificate")

        self.aes_gcm: AESGCM = None

    def process(self, data: bytes = b"") -> bytes | int:
        if data:
            # We have received a message from the other party
            message = Packet.from_json(data.decode())

            match message.type:
                case PacketType.PUB_SIGN_CERT:
                    print(f"Received PUB_SIGN_CERT from receiver")

                    message = self._handle_pub_sign_cert(message)
                    if message == -1:
                        return -1

                    return message.to_json().encode()

                case PacketType.CONN_SUCCESS:
                    print(f"Received CONN_SUCCESS from receiver")

                    shared_key = self.dh_private_key.exchange(self.receiver_dh_pub_key)
                    key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"handshake data",
                    ).derive(shared_key)

                    self.aes_gcm = AESGCM(key)
                    print("You can now send messages")

                case PacketType.MSG_ACK:
                    print("Message sent successfully")

                case PacketType.MSG_ERROR:
                    print("Error in message transmission")
                    return -1

                case _:
                    print("Unknown message type received")
                    return -1
        else:
            # Create the first message to send
            # to the other party during the key exchange
            # process

            public_key = self.dh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            message = create_pub_key_message(public_key)
            return message.to_json().encode()

        # If aes_gcm is set, it means we have already exchange a secret
        # and can prompt the user for messages
        if self.aes_gcm is not None:
            print()
            print("Enter message to send (or 'exit' to quit)")
            
            message = input("> ")
            if message == "exit" or not message:
                return -1

            nounce = os.urandom(12)
            ciphertext = self.aes_gcm.encrypt(nounce, message.encode(), None)
            message = create_content_message(ciphertext, nounce)
            return message.to_json().encode()
        
    def _handle_pub_sign_cert(self, message: Packet) -> Packet | int:
        self.receiver_dh_pub_key = serialization.load_pem_public_key(
            b64.b64decode(message.content["pub_key"].encode())
        )

        self.receiver_certificate = x509.load_pem_x509_certificate(
            b64.b64decode(message.content["cert"][0].encode())
        )
        self.receiver_certificate_name = message.content["cert"][1]

        # Verify certificate
        if not self.certificate_validator.validate_certificate(
            self.receiver_certificate,
            self.receiver_certificate_name,
        ):
            print("Received invalid certificate")
            return -1
        
        # Verify signature
        signature = b64.b64decode(message.content["signature"].encode())
        both_public_keys = utils.join_pair(
            self.receiver_dh_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            self.dh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

        try:
            self.receiver_certificate.public_key().verify(
                signature,
                both_public_keys,
            )
        except InvalidSignature:
            print("Invalid signature")
            return -1
        
        # Sign both public keys in reverse order and send with certificate
        both_public_keys = utils.join_pair(
            self.dh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            self.receiver_dh_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        signature = self.ed25519_private_key.sign(both_public_keys)

        certificate = self.certificate.public_bytes(encoding=serialization.Encoding.PEM)
        message = create_sign_cert_message(signature, certificate, self.certificate_name)
        return message

async def tcp_sender(creds: str):
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    sender = Sender(creds)

    try:
        message = sender.process()
        while message != -1:
            if message:
                writer.write(message)
                message = await reader.read(MAX_MESSAGE_SIZE)
            
            message = sender.process(message)

        writer.write(b"\n")
        print("Socket closed")
        writer.close()
        exit()
    except Exception as e:
        print(f"Socket closed due to {e.__repr__()}!")
        writer.write(b"\n")
        writer.close()
        exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sender")
    parser.add_argument(
        "-c",
        "--creds",
        type=str,
        required=True,
        help="Path to the PKCS12 file",
    )

    args = parser.parse_args()
    if not os.path.exists(args.creds):
        print(f"PKCS12 file {args.creds} does not exist")
        exit(1)

    asyncio.run(tcp_sender(args.creds))
