import enum
import json
import base64 as b64
from typing import Any, Self

@enum.unique
class PacketType(enum.Enum):
    PUB_KEY = 0
    PUB_SIGN_CERT = 1
    SIGN_CERT = 2
    CONN_SUCCESS = 3
    CONTENT = 4
    MSG_ACK = 5
    MSG_ERROR = 6

class Packet:
    def __init__(self, type: PacketType, content: Any) -> Self:
        self.type = type
        self.content = content

    def _to_dict(self) -> dict:
        return (
            {"type": self.type.value, "content": self.content}
            if not isinstance(self.content, bytes)
            else {"type": self.type.value, "content": self.content.decode("utf-8")}
        )

    @staticmethod
    def _from_dict(data) -> Self:
        return Packet(PacketType(data["type"]), data["content"])

    def to_json(self) -> str:
        return json.dumps(self._to_dict())

    @staticmethod
    def from_json(json_str) -> Self:
        return Packet._from_dict(json.loads(json_str))


def _create_message(type, content: Any = None) -> Packet:
    return Packet(type, content)

def create_pub_key_message(pub_key: bytes) -> Packet:
    return _create_message(PacketType.PUB_KEY, b64encode(pub_key))

def create_pub_sign_cert_message(
    pub_key: bytes, signature: bytes, certificate: bytes, certificate_name: str
) -> Packet:
    content = {
        "pub_key": b64encode(pub_key),
        "signature": b64encode(signature),
        "cert": [b64encode(certificate), certificate_name],
    }

    return _create_message(PacketType.PUB_SIGN_CERT, content)

def create_sign_cert_message(
    signature: bytes, certificate: bytes, certificate_name: str
) -> Packet:
    content = {
        "signature": b64encode(signature),
        "cert": [b64encode(certificate), certificate_name],
    }

    return _create_message(PacketType.SIGN_CERT, content)

def create_conn_success_message() -> Packet:
    return _create_message(PacketType.CONN_SUCCESS)

def create_content_message(content: bytes, nounce: bytes) -> Packet:
    content = {
        "message": b64encode(content),
        "nounce": b64encode(nounce),
    }

    return _create_message(PacketType.CONTENT, content)

def create_msg_ack_message() -> Packet:
    return _create_message(PacketType.MSG_ACK)

def create_msg_error_message(error: str) -> Packet:
    return _create_message(PacketType.MSG_ERROR, error.encode("utf-8"))

def b64encode(data: bytes) -> bytes:
    return b64.b64encode(data).decode()

def b64decode(data: bytes) -> bytes:
    return b64.b64decode(data.encode())
