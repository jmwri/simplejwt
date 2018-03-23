from typing import Union
import json
import hmac
import hashlib

from simplejwt import util

algorithms = {
    'HS256': hashlib.sha256
}


def get_algorithm(alg: str):
    if alg not in algorithms:
        raise ValueError('Invalid algorithm: {:s}'.format(alg))
    return algorithms[alg]


def encode(secret: Union[str, bytes], payload: dict, alg='HS256'):
    secret = util.to_bytes(secret)

    header = {
        'type': 'JWT',
        'alg': alg
    }
    header_json = util.to_bytes(json.dumps(header))
    header_b64 = util.b64_encode(header_json)
    payload_json = util.to_bytes(json.dumps(payload))
    payload_b64 = util.b64_encode(payload_json)

    pre_signature = util.join(header_b64, payload_b64)
    algorithm = get_algorithm(alg)
    signature = hmac\
        .new(secret, msg=pre_signature, digestmod=algorithm)\
        .digest()
    signature_b64 = util.b64_encode(signature)

    token = util.join(pre_signature, signature_b64)
    return util.from_bytes(token)
