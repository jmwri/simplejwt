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

default_alg = 'HS256'


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
        self.token = None
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

    @property
    def issuer(self):
        return self.registered_claims.get('iss')

    @issuer.setter
    def issuer(self, issuer: str):
        if 'iss' not in self.registered_claims:
            self.registered_claims['iss'] = issuer

    @property
    def subject(self):
        return self.registered_claims.get('sub')

    @subject.setter
    def subject(self, subject: str):
        if 'sub' not in self.registered_claims:
            self.registered_claims['sub'] = subject

    @property
    def audience(self):
        return self.registered_claims.get('aud')

    @audience.setter
    def audience(self, audience: str):
        if 'aud' not in self.registered_claims:
            self.registered_claims['aud'] = audience

    @property
    def valid_to(self):
        return self.registered_claims.get('exp')

    @valid_to.setter
    def valid_to(self, valid_to: int):
        if 'exp' not in self.registered_claims:
            self.registered_claims['exp'] = valid_to

    @property
    def valid_from(self):
        return self.registered_claims.get('nbf')

    @valid_from.setter
    def valid_from(self, valid_from: int):
        if 'nbf' not in self.registered_claims:
            self.registered_claims['nbf'] = valid_from

    @property
    def issued_at(self):
        return self.registered_claims.get('iss')

    @issued_at.setter
    def issued_at(self, issued_at: int):
        if 'iat' not in self.registered_claims:
            self.registered_claims['iat'] = issued_at

    @property
    def id(self):
        return self.registered_claims.get('jti')

    @id.setter
    def id(self, id: str):
        if 'jti' not in self.registered_claims:
            self.registered_claims['jti'] = id

    def encode(self):
        payload = {}
        payload.update(self.registered_claims)
        payload.update(self.payload)
        self.token = encode(self.secret, payload, self.alg, self.header)
        return self.token


def make(secret: Union[str, bytes], payload: dict, alg: str = default_alg,
         **kwargs):
    jwt = Jwt(secret, payload, alg, **kwargs)
    return jwt.encode()


def encode(secret: Union[str, bytes], payload: dict, alg: str = default_alg,
           header: dict = None):
    secret = util.to_bytes(secret)

    if header:
        header = header.copy()
    else:
        header = {}
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


def decode(secret: Union[str, bytes], token: Union[str, bytes],
           alg: str = default_alg):
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
