from typing import Union
import json
import hmac
import hashlib
from base64 import urlsafe_b64encode

algorithms = {
    'HS256': hashlib.sha256
}


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


def get_algorithm(alg: str):
    if alg not in algorithms:
        raise ValueError('Invalid algorithm: {:s}'.format(alg))
    return algorithms[alg]


def encode(secret: Union[str, bytes], payload: dict, alg='HS256'):
    secret = to_bytes(secret)

    header = {
        'type': 'JWT',
        'alg': alg
    }
    header_json = to_bytes(json.dumps(header))
    header_b64 = b64_encode(header_json)
    payload_json = to_bytes(json.dumps(payload))
    payload_b64 = b64_encode(payload_json)

    pre_signature = join(header_b64, payload_b64)
    algorithm = get_algorithm(alg)
    signature = hmac\
        .new(secret, msg=pre_signature, digestmod=algorithm)\
        .digest()
    signature_b64 = b64_encode(signature)

    token = join(pre_signature, signature_b64)
    return from_bytes(token)
