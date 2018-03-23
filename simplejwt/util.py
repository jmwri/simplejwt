from typing import Union
from base64 import urlsafe_b64encode


def b64_encode(data: bytes):
    """
    Base64 encodes a byte string, removing any padding of =
    """
    encoded = urlsafe_b64encode(data)
    return encoded.replace(b'=', b'')


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
