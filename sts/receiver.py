import asyncio
import base64 as b64
import logging
import os
import sys

from common.protocol import *
from common.cerificate_validator import CertificateValidator
from common import utils

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

PORT = 8889
MAX_MESSAGE_SIZE = 8192
PKC12_FILE = "data/credentials/receiver.p12"

class Receiver:
    def __init__(self, creds: str):
        self.dh_private_key = X25519PrivateKey.generate()
        self.sender_dh_pub_key: X25519PublicKey = None
        self.sender_certificate: Certificate = None
        self.sender_certificate_name: str = None

        self.ed25519_private_key, self.certificate, self.ca_certificate = utils.get_userdata(creds)

        base_name = os.path.basename(creds)
        name_without_ext, _ = os.path.splitext(base_name)
        self.certificate_name = name_without_ext
        
        self.certificate_validator = CertificateValidator()
        if not self.certificate_validator.validate_certificate(self.certificate, self.certificate_name):
            raise ValueError("Invalid certificate")

        self.aes_gcm: AESGCM = None

    async def process(self, data: bytes = b"") -> bytes | int:
        message = Packet.from_json(data.decode())

        match message.type:
            case PacketType.PUB_KEY:
                logging.info("Received PUB_KEY from sender")

                message = self._handle_pub_key(message)
                if message == -1:
                    return -1

                return message.to_json().encode()

            case PacketType.SIGN_CERT:
                logging.info("Received SIGN_CERT from sender")

                message = self._handle_sign_cert(message)
                if message == -1:
                    return -1

                return message.to_json().encode() 

            case PacketType.CONTENT:
                content = message.content
                message = b64.b64decode(content["message"].encode())
                nounce = b64.b64decode(content["nounce"].encode())

                decrypted = self.aes_gcm.decrypt(nounce, message, None)
                logging.info(f"Received message: {decrypted.decode()}")

                message = create_msg_ack_message()
                return message.to_json().encode()

            case _:
                logging.warning("Received an invalid request")
                message = create_msg_error_message("Invalid request")
                return message.to_json().encode()
            
    def _handle_pub_key(self, message: Packet) -> Packet | int:
        self.sender_dh_pub_key = serialization.load_pem_public_key(
            b64.b64decode(message.content.encode())
        )

        both_public_keys = utils.join_pair(
            self.dh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            self.sender_dh_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

        signature = self.ed25519_private_key.sign(both_public_keys)
        public_key = self.dh_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        message = create_pub_sign_cert_message(
            public_key,
            signature,
            self.certificate.public_bytes(encoding=serialization.Encoding.PEM),
            self.certificate_name,
        )

        return message
    
    def _handle_sign_cert(self, message: Packet) -> Packet | int:
        self.sender_certificate = x509.load_pem_x509_certificate(
            b64.b64decode(message.content["cert"][0].encode())
        )
        self.sender_certificate_name = message.content["cert"][1]

        # Verify certificate
        if not self.certificate_validator.validate_certificate(
            self.sender_certificate,
            self.sender_certificate_name,
        ):
            logging.warning("Received invalid certificate")
            return -1
        
        # Verify signature
        signature = b64.b64decode(message.content["signature"].encode())
        both_public_keys = utils.join_pair(
            self.sender_dh_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            self.dh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

        try:
            self.sender_certificate.public_key().verify(
                signature,
                both_public_keys,
            )
        except InvalidSignature:
            logging.warning("Invalid signature")
            return -1
        
        # Derive shared key
        shared_key = self.dh_private_key.exchange(self.sender_dh_pub_key)
        shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

        self.aes_gcm = AESGCM(shared_key)
        logging.info("Shared key derived successfully")

        message = create_conn_success_message()
        return message

async def handle_echo(reader, writer):
    receiver = Receiver(PKC12_FILE)

    try:
        data = await reader.read(MAX_MESSAGE_SIZE)
        while True:
            if not data:
                continue

            if data[:1] == b"\n":
                break

            data = await receiver.process(data)
            writer.write(data)
            await writer.drain()
            data = await reader.read(MAX_MESSAGE_SIZE)
        
        logging.info("Connection from sender ended")
        writer.close()
    except Exception as e:
        logging.info(f"Some error occurred: {e.__repr__()}")
        writer.close()

def tcp_echo_receiver():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, "127.0.0.1", PORT)
    server = loop.run_until_complete(coro)
    logging.info("Serving on {}".format(server.sockets[0].getsockname()))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Receiver closed manually")
        exit(0)
    except Exception as e:
        logging.error(f"Receiver closed due to {e.__repr()}")
        exit(1)
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

if __name__ == "__main__":
    logging.basicConfig(
        filename="receiver.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    logging.getLogger().addHandler(console_handler)

    tcp_echo_receiver()
