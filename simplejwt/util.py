from typing import Union
from base64 import urlsafe_b64encode, urlsafe_b64decode


def b64_encode(data: bytes) -> bytes:
    """
    :param data: Data the encode.
    :type data: bytes
    :return: Base 64 encoded data with padding removed.
    :rtype: bytes
    """
    encoded = urlsafe_b64encode(data)
    return encoded.replace(b'=', b'')


def b64_decode(data: bytes) -> bytes:
    """
    :param data: Base 64 encoded data to decode.
    :type data: bytes
    :return: Base 64 decoded data.
    :rtype: bytes
    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'=' * (4 - missing_padding)
    return urlsafe_b64decode(data)


def to_bytes(data: Union[str, bytes]) -> bytes:
    """
    :param data: Data to convert to bytes.
    :type data: Union[str, bytes]
    :return: `data` encoded to UTF8.
    :rtype: bytes
    """
    if isinstance(data, bytes):
        return data
    return data.encode('utf-8')


def from_bytes(data: Union[str, bytes]) -> str:
    """
    :param data: A UTF8 byte string.
    :type data: Union[str, bytes]
    :return: `data` decoded from UTF8.
    :rtype: str
    """
    if isinstance(data, str):
        return data
    return str(data, 'utf-8')


def join(*args: bytes) -> bytes:
    """
    Join any amount of byte strings with a `.`.
    :param args: Any amount of byte strings.
    :type args: bytes
    :return: All provided bytes concatenated with `.`.
    :rtype: bytes
    """
    return b'.'.join(args)
