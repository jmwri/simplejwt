from typing import Union
from base64 import urlsafe_b64encode, urlsafe_b64decode


def b64_encode(data: bytes):
    """
    Base64 encodes a byte string, removing any padding of =
    """
    encoded = urlsafe_b64encode(data)
    return encoded.replace(b'=', b'')


def b64_decode(data: bytes):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'=' * (4 - missing_padding)
    return urlsafe_b64decode(data)


def to_bytes(data: Union[str, bytes]):
    if isinstance(data, bytes):
        return data
    return data.encode('utf-8')


def from_bytes(data: Union[str, bytes]):
    if isinstance(data, str):
        return data
    return str(data, 'utf-8')


def join(*args: bytes):
    return b'.'.join(args)
