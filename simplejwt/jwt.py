from typing import Union
import json
import hmac
import hashlib
from datetime import datetime

from simplejwt import util
from simplejwt.exception import InvalidSignatureError

algorithms = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}

default_alg = 'HS256'

registered_claims = {
    'issuer': 'iss',
    'subject': 'sub',
    'audience': 'aud',
    'valid_to': 'exp',
    'valid_from': 'nbf',
    'issued_at': 'iat',
    'id': 'jti',
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


class Jwt:
    def __init__(self, secret: Union[str, bytes], payload: dict = None,
                 alg: str = default_alg, header: dict = None,
                 issuer: str = None, subject: str = None, audience: str = None,
                 valid_to: int = None, valid_from: int = None,
                 issued_at: int = None, id: str = None):
        self.secret = secret
        self.payload = payload or {}
        self.alg = alg
        self.header = header or {}
        self.registered_claims = {}
        if issuer:
            self.issuer = issuer
        if subject:
            self.subject = subject
        if audience:
            self.audience = audience
        if valid_to:
            self.valid_to = valid_to
        if valid_from:
            self.valid_from = valid_from
        if issued_at:
            self.issued_at = issued_at
        if id:
            self.id = id
        self._pop_claims_from_payload()

    @property
    def issuer(self):
        return self.registered_claims.get('iss')

    @issuer.setter
    def issuer(self, issuer: str):
        self.registered_claims['iss'] = issuer

    @property
    def subject(self):
        return self.registered_claims.get('sub')

    @subject.setter
    def subject(self, subject: str):
        self.registered_claims['sub'] = subject

    @property
    def audience(self):
        return self.registered_claims.get('aud')

    @audience.setter
    def audience(self, audience: str):
        self.registered_claims['aud'] = audience

    @property
    def valid_to(self):
        return self.registered_claims.get('exp')

    @valid_to.setter
    def valid_to(self, valid_to: int):
        self.registered_claims['exp'] = valid_to

    @property
    def valid_from(self):
        return self.registered_claims.get('nbf')

    @valid_from.setter
    def valid_from(self, valid_from: int):
        self.registered_claims['nbf'] = valid_from

    @property
    def issued_at(self):
        return self.registered_claims.get('iat')

    @issued_at.setter
    def issued_at(self, issued_at: int):
        self.registered_claims['iat'] = issued_at

    @property
    def id(self):
        return self.registered_claims.get('jti')

    @id.setter
    def id(self, id: str):
        self.registered_claims['jti'] = id

    def valid(self, time: int = None):
        time = time or int(datetime.utcnow().timestamp())
        if time < self.valid_from:
            return False
        if time > self.valid_to:
            return False
        return True

    def _pop_claims_from_payload(self):
        claims_in_payload = [k for k in self.payload.keys() if
                             k in registered_claims.values()]
        for name in claims_in_payload:
            self.registered_claims[name] = self.payload.pop(name)

    def encode(self):
        payload = {}
        payload.update(self.registered_claims)
        payload.update(self.payload)
        return encode(self.secret, payload, self.alg, self.header)

    @staticmethod
    def decode(secret: Union[str, bytes], token: Union[str, bytes],
               alg: str = default_alg):
        header, payload = _decode(secret, token, alg)
        return Jwt(secret, payload, alg, header)


def make(secret: Union[str, bytes], payload: dict, alg: str = default_alg,
         **kwargs):
    jwt = Jwt(secret, payload, alg, **kwargs)
    return jwt.encode()


def encode(secret: Union[str, bytes], payload: dict = None,
           alg: str = default_alg, header: dict = None):
    secret = util.to_bytes(secret)

    payload = payload or {}
    header = header or {}

    if isinstance(header, dict):
        header = header.copy()
        header.update({
            'type': 'JWT',
            'alg': alg
        })

    header_json = util.to_bytes(json.dumps(header))
    header_b64 = util.b64_encode(header_json)
    payload_json = util.to_bytes(json.dumps(payload))
    payload_b64 = util.b64_encode(payload_json)

    pre_signature = util.join(header_b64, payload_b64)
    signature = _hash(secret, pre_signature, alg)
    signature_b64 = util.b64_encode(signature)

    token = util.join(pre_signature, signature_b64)
    return util.from_bytes(token)


def _decode(secret: Union[str, bytes], token: Union[str, bytes],
            alg: str = default_alg):
    secret = util.to_bytes(secret)
    token = util.to_bytes(token)
    pre_signature, signature_segment = token.rsplit(b'.', 1)
    header_b64, payload_b64 = pre_signature.split(b'.')
    header_json = util.b64_decode(header_b64)
    header = json.loads(util.from_bytes(header_json))
    payload_json = util.b64_decode(payload_b64)
    payload = json.loads(util.from_bytes(payload_json))

    if not isinstance(header, dict):
        raise RuntimeError('Invalid header: {}'.format(header))
    if not isinstance(payload, dict):
        raise RuntimeError('Invalid payload: {}'.format(payload))

    signature = util.b64_decode(signature_segment)
    calculated_signature = _hash(secret, pre_signature, alg)

    if not hmac.compare_digest(signature, calculated_signature):
        raise InvalidSignatureError('Invalid signature')
    return header, payload


def decode(secret: Union[str, bytes], token: Union[str, bytes],
           alg: str = default_alg):
    _, payload = _decode(secret, token, alg)
    return payload
