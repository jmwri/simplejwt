from typing import Union, Callable, Tuple
import json
import hmac
import hashlib
from datetime import datetime

from simplejwt import util
from simplejwt.exception import InvalidSignatureError, InvalidHeaderError, \
    InvalidPayloadError

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


def get_algorithm(alg: str) -> Callable:
    """
    :param alg: The name of the requested `JSON Web Algorithm <https://tools.ietf.org/html/rfc7519#ref-JWA>`_. `RFC7518 <https://tools.ietf.org/html/rfc7518#section-3.2>`_ is related.
    :type alg: str
    :return: The requested algorithm.
    :rtype: Callable
    :raises: ValueError
    """
    if alg not in algorithms:
        raise ValueError('Invalid algorithm: {:s}'.format(alg))
    return algorithms[alg]


def _hash(secret: bytes, data: bytes, alg: str) -> bytes:
    """
    Create a new HMAC hash.

    :param secret: The secret used when hashing data.
    :type secret: bytes
    :param data: The data to hash.
    :type data: bytes
    :param alg: The algorithm to use when hashing `data`.
    :type alg: str
    :return: New HMAC hash.
    :rtype: bytes
    """
    algorithm = get_algorithm(alg)
    return hmac \
        .new(secret, msg=data, digestmod=algorithm) \
        .digest()


class Jwt:
    """
    A self-contained class that can manage encoding and decoding tokens.
    """

    def __init__(self, secret: Union[str, bytes], payload: dict = None,
                 alg: str = default_alg, header: dict = None,
                 issuer: str = None, subject: str = None, audience: str = None,
                 valid_to: int = None, valid_from: int = None,
                 issued_at: int = None, id: str = None):
        """
        :param secret: The secret used to encode the token.
        :type secret: Union[str, bytes]
        :param payload: The payload to be encoded in the token.
        :type payload: dict
        :param alg: The algorithm used to hash the token.
        :type alg: str
        :param header: The header of the token.
        :type header: dict
        :param issuer: The issuer of the token.
        :type issuer: str
        :param subject: The subject of the token.
        :type subject: str
        :param audience: The audience of the token.
        :type audience: str
        :param valid_to: Date the token expires as a timestamp.
        :type valid_to: int
        :param valid_from: Date the token is valid from as timestamp.
        :type valid_from: int
        :param issued_at: Date the token was issued as a timestamp.
        :type issued_at: int
        :param id: The unique ID of the token.
        :type id: str
        """
        self.secret = secret
        self.payload = payload or {}
        self.alg = alg
        self._header = {}
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
    def header(self) -> dict:
        """
        :return: Token header.
        :rtype: dict
        """
        header = {}
        if isinstance(self._header, dict):
            header = self._header.copy()
            header.update(self._header)
        header.update({
            'type': 'JWT',
            'alg': self.alg
        })
        return header

    @header.setter
    def header(self, header: dict):
        """
        Sets the token header.

        :param header: New header
        :type header: dict
        """
        self._header = header

    @property
    def issuer(self) -> Union[str, None]:
        """
        :return: Issuer (`iss`) claim from the token.
        :rtype: Union[str, None]
        """
        return self.registered_claims.get('iss')

    @issuer.setter
    def issuer(self, issuer: str):
        """
        Sets the issuer (`iss`) claim in the token.

        :param issuer: New value.
        :type issuer: str
        """
        self.registered_claims['iss'] = issuer

    @property
    def subject(self) -> Union[str, None]:
        """
        :return: Subject (`sub`) claim from the token.
        :rtype: Union[str, None]
        """
        return self.registered_claims.get('sub')

    @subject.setter
    def subject(self, subject: str):
        """
        Sets the subject (`sub`) claim in the token.

        :param subject: New value.
        :type subject: str
        """
        self.registered_claims['sub'] = subject

    @property
    def audience(self) -> Union[str, None]:
        """
        :return: Audience (`aud`) claim from the token.
        :rtype: Union[str, None]
        """
        return self.registered_claims.get('aud')

    @audience.setter
    def audience(self, audience: str):
        """
        Sets the audience (`aud`) claim in the token.

        :param audience: New value.
        :type audience: str
        """
        self.registered_claims['aud'] = audience

    @property
    def valid_to(self) -> Union[int, None]:
        """
        :return: Expires (`exp`) claim from the token.
        :rtype: Union[int, None]
        """
        return self.registered_claims.get('exp')

    @valid_to.setter
    def valid_to(self, valid_to: int):
        """
        Sets the expires (`exp`) claim in the token.

        :param valid_to: New value.
        :type valid_to: int
        """
        self.registered_claims['exp'] = valid_to

    @property
    def valid_from(self) -> Union[int, None]:
        """
        :return: Not before (`nbf`) claim from the token.
        :rtype: Union[int, None]
        """
        return self.registered_claims.get('nbf')

    @valid_from.setter
    def valid_from(self, valid_from: int):
        """
        Sets the not before (`nbf`) claim in the token.

        :param valid_from: New value.
        :type valid_from: int
        """
        self.registered_claims['nbf'] = valid_from

    @property
    def issued_at(self) -> Union[int, None]:
        """
        :return: Issued at (`iat`) claim from the token.
        :rtype: Union[int, None]
        """
        return self.registered_claims.get('iat')

    @issued_at.setter
    def issued_at(self, issued_at: int):

        """
        Sets the issued at (`iat`) claim in the token.

        :param issued_at: New value.
        :type issued_at: int
        """
        self.registered_claims['iat'] = issued_at

    @property
    def id(self) -> Union[str, None]:
        """
        :return: ID (`jti`) claim from the token.
        :rtype: Union[str, None]
        """
        return self.registered_claims.get('jti')

    @id.setter
    def id(self, id: str):
        """
        Sets the ID (`jti`) claim in the token.

        :param id: New value.
        :type id: str
        """
        self.registered_claims['jti'] = id

    def valid(self, time: int = None) -> bool:
        """
        Is the token valid? This method only checks the timestamps within the
        token and compares them against the current time if none is provided.

        :param time: The timestamp to validate against
        :type time: Union[int, None]
        :return: The validity of the token.
        :rtype: bool
        """
        if time is None:
            epoch = datetime(1970, 1, 1, 0, 0, 0)
            now = datetime.utcnow()
            time = int((now - epoch).total_seconds())
        if isinstance(self.valid_from, int) and time < self.valid_from:
            return False
        if isinstance(self.valid_to, int) and time > self.valid_to:
            return False
        return True

    def _pop_claims_from_payload(self):
        """
        Check for registered claims in the payload and move them to the
        registered_claims property, overwriting any extant claims.
        """
        claims_in_payload = [k for k in self.payload.keys() if
                             k in registered_claims.values()]
        for name in claims_in_payload:
            self.registered_claims[name] = self.payload.pop(name)

    def encode(self) -> str:
        """
        Create a token based on the data held in the class.

        :return: A new token
        :rtype: str
        """
        payload = {}
        payload.update(self.registered_claims)
        payload.update(self.payload)
        return encode(self.secret, payload, self.alg, self.header)

    @staticmethod
    def decode(secret: Union[str, bytes], token: Union[str, bytes],
               alg: str = default_alg) -> 'Jwt':
        """
        Decodes the given token into an instance of `Jwt`.

        :param secret: The secret used to decode the token. Must match the
            secret used when creating the token.
        :type secret: Union[str, bytes]
        :param token: The token to decode.
        :type token: Union[str, bytes]
        :param alg: The algorithm used to decode the token. Must match the
            algorithm used when creating the token.
        :type alg: str
        :return: The decoded token.
        :rtype: `Jwt`
        """
        header, payload = decode(secret, token, alg)
        return Jwt(secret, payload, alg, header)

    def compare(self, jwt: 'Jwt', compare_dates: bool = False) -> bool:
        """
        Compare against another `Jwt`.

        :param jwt: The token to compare against.
        :type jwt: Jwt
        :param compare_dates: Should the comparision take dates into account?
        :type compare_dates: bool
        :return: Are the two Jwt's the same?
        :rtype: bool
        """
        if self.secret != jwt.secret:
            return False
        if self.payload != jwt.payload:
            return False
        if self.alg != jwt.alg:
            return False
        if self.header != jwt.header:
            return False
        expected_claims = self.registered_claims
        actual_claims = jwt.registered_claims
        if not compare_dates:
            strip = ['exp', 'nbf', 'iat']
            expected_claims = {k: {v if k not in strip else None} for k, v in
                               expected_claims.items()}
            actual_claims = {k: {v if k not in strip else None} for k, v in
                             actual_claims.items()}
        if expected_claims != actual_claims:
            return False
        return True


def encode(secret: Union[str, bytes], payload: dict = None,
           alg: str = default_alg, header: dict = None) -> str:
    """
    :param secret: The secret used to encode the token.
    :type secret: Union[str, bytes]
    :param payload: The payload to be encoded in the token.
    :type payload: dict
    :param alg: The algorithm used to hash the token.
    :type alg: str
    :param header: The header to be encoded in the token.
    :type header: dict
    :return: A new token
    :rtype: str
    """
    secret = util.to_bytes(secret)

    payload = payload or {}
    header = header or {}

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
           alg: str = default_alg) -> Tuple[dict, dict]:
    """
    Decodes the given token's header and payload and validates the signature.

    :param secret: The secret used to decode the token. Must match the
        secret used when creating the token.
    :type secret: Union[str, bytes]
    :param token: The token to decode.
    :type token: Union[str, bytes]
    :param alg: The algorithm used to decode the token. Must match the
        algorithm used when creating the token.
    :type alg: str
    :return: The decoded header and payload.
    :rtype: Tuple[dict, dict]
    """
    secret = util.to_bytes(secret)
    token = util.to_bytes(token)
    pre_signature, signature_segment = token.rsplit(b'.', 1)
    header_b64, payload_b64 = pre_signature.split(b'.')
    try:
        header_json = util.b64_decode(header_b64)
        header = json.loads(util.from_bytes(header_json))
    except (json.decoder.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise InvalidHeaderError('Invalid header')
    try:
        payload_json = util.b64_decode(payload_b64)
        payload = json.loads(util.from_bytes(payload_json))
    except (json.decoder.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise InvalidPayloadError('Invalid payload')

    if not isinstance(header, dict):
        raise InvalidHeaderError('Invalid header: {}'.format(header))
    if not isinstance(payload, dict):
        raise InvalidPayloadError('Invalid payload: {}'.format(payload))

    signature = util.b64_decode(signature_segment)
    calculated_signature = _hash(secret, pre_signature, alg)

    if not compare_signature(signature, calculated_signature):
        raise InvalidSignatureError('Invalid signature')
    return header, payload


def compare_signature(expected: Union[str, bytes],
                      actual: Union[str, bytes]) -> bool:
    """
    Compares the given signatures.

    :param expected: The expected signature.
    :type expected: Union[str, bytes]
    :param actual: The actual signature.
    :type actual: Union[str, bytes]
    :return: Do the signatures match?
    :rtype: bool
    """
    expected = util.to_bytes(expected)
    actual = util.to_bytes(actual)
    return hmac.compare_digest(expected, actual)


def compare_token(expected: Union[str, bytes],
                  actual: Union[str, bytes]) -> bool:
    """
    Compares the given tokens.

    :param expected: The expected token.
    :type expected: Union[str, bytes]
    :param actual: The actual token.
    :type actual: Union[str, bytes]
    :return: Do the tokens match?
    :rtype: bool
    """
    expected = util.to_bytes(expected)
    actual = util.to_bytes(actual)
    _, expected_sig_seg = expected.rsplit(b'.', 1)
    _, actual_sig_seg = actual.rsplit(b'.', 1)
    expected_sig = util.b64_decode(expected_sig_seg)
    actual_sig = util.b64_decode(actual_sig_seg)
    return compare_signature(expected_sig, actual_sig)
