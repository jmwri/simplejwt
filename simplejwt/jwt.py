from typing import Union
import json
import hmac
import hashlib

from simplejwt import util
from simplejwt.exception import InvalidSignatureError

algorithms = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def get_algorithm(alg: str):
    if alg not in algorithms:
        raise ValueError('Invalid algorithm: {:s}'.format(alg))
    return algorithms[alg]


def _hash(secret: bytes, data: bytes, alg: str) -> bytes:
    algorithm = get_algorithm(alg)
    return hmac \
        .new(secret, msg=data, digestmod=algorithm) \
        .digest()


def make(secret: Union[str, bytes], payload: dict, alg='HS256',
         issuer: str = None, subject: str = None, audience: str = None,
         valid_to: int = None, valid_from: int = None, issued_at: int = None,
         id: str = None):
    new_payload = payload.copy()
    if issuer and 'iss' not in new_payload:
        new_payload['iss'] = issuer
    if subject and 'sub' not in new_payload:
        new_payload['sub'] = subject
    if audience and 'aud' not in new_payload:
        new_payload['aud'] = audience
    if valid_to and 'exp' not in new_payload:
        new_payload['exp'] = valid_to
    if valid_from and 'nbf' not in new_payload:
        new_payload['nbf'] = valid_from
    if issued_at and 'iat' not in new_payload:
        new_payload['iat'] = issued_at
    if id and 'jti' not in new_payload:
        new_payload['jti'] = id
    return encode(secret, new_payload, alg)


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
    signature = _hash(secret, pre_signature, alg)
    signature_b64 = util.b64_encode(signature)

    token = util.join(pre_signature, signature_b64)
    return util.from_bytes(token)


def decode(secret: Union[str, bytes], token: Union[str, bytes], alg='HS256'):
    secret = util.to_bytes(secret)
    token = util.to_bytes(token)
    pre_signature, signature_segment = token.rsplit(b'.', 1)
    payload_b64 = pre_signature.split(b'.', 1)[1]
    payload_json = util.b64_decode(payload_b64)
    payload = json.loads(util.from_bytes(payload_json))

    if not isinstance(payload, dict):
        raise RuntimeError('Invalid payload: {}'.format(payload))

    signature = util.b64_decode(signature_segment)
    calculated_signature = _hash(secret, pre_signature, alg)

    if not hmac.compare_digest(signature, calculated_signature):
        raise InvalidSignatureError('Invalid signature')
    return payload
