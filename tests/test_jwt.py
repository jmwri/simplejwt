import pytest
import hashlib

from simplejwt import jwt, util
from simplejwt.exception import InvalidSignatureError

test_tokens = {
    'HS256': ('eyJ0eXBlIjogIkpXVCIsICJhbGciOiAiSFMyNTYifQ.'
              'eyJ0ZXN0aW5nIjogdHJ1ZX0.'
              'rAuMC7c8hCaBZPmGm-n-23gR3Pa_qvdPUr0-WuDJBpc'),
    'HS384': ('eyJ0eXBlIjogIkpXVCIsICJhbGciOiAiSFMzODQifQ.'
              'eyJ0ZXN0aW5nIjogdHJ1ZX0.'
              'YxqUh3d1W3d_RzG7dSFDjSNL3R4fvEWy618r4EsTT1e12bD1lA9amBRI5eMQ6u7'
              'q'),
    'HS512': ('eyJ0eXBlIjogIkpXVCIsICJhbGciOiAiSFM1MTIifQ.'
              'eyJ0ZXN0aW5nIjogdHJ1ZX0.'
              '2qlY1c-bqYkk1mClVkVmlEnj6PUZK-qvXvDYlyvEdIdmrQrvBcF_hL0Il2sZRJp'
              'j3KRWj5LAYrz6bKlfoxk2WQ'),
}

test_token_data = {
    'secret': 'super_secret',
    'payload': {
        'testing': True
    }
}

registered_claims = {
    'issuer': 'iss',
    'subject': 'sub',
    'audience': 'aud',
    'valid_to': 'exp',
    'valid_from': 'nbf',
    'issued_at': 'iat',
    'id': 'jti',
}

test_registered_claims = {
    'issuer': 'test_issuer',
    'subject': 'test_subject',
    'audience': 'test_audience',
    'valid_to': 789,
    'valid_from': 456,
    'issued_at': 123,
    'id': 'test_id',
}


def test_get_algorithm_hs256():
    assert jwt.get_algorithm('HS256') is hashlib.sha256


def test_get_algorithm_hs384():
    assert jwt.get_algorithm('HS384') is hashlib.sha384


def test_get_algorithm_hs512():
    assert jwt.get_algorithm('HS512') is hashlib.sha512


def test_get_algorithm_incorrect():
    with pytest.raises(ValueError):
        jwt.get_algorithm('magic')


def test_cover_all_algorithms():
    for alg in jwt.algorithms:
        assert alg in test_tokens


def test_encode():
    token_data = {
        'secret': 'super_secret',
        'payload': {
            'testing': True
        }
    }
    for alg, token in test_tokens.items():
        assert jwt.encode(
            token_data['secret'],
            token_data['payload'],
            alg
        ) == token


def test_make_claims():
    for name, abb in registered_claims.items():
        args = {
            'secret': test_token_data['secret'],
            'payload': test_token_data['payload'],
            name: test_registered_claims[name]
        }
        token = jwt.make(**args)
        payload = jwt.decode(test_token_data['secret'], token)
        assert payload[abb] == test_registered_claims[name]


def test_make_precedence():
    token = jwt.make(test_token_data['secret'], {'iss': 'usr_defined_idd'},
                     issuer='my_iss')
    payload = jwt.decode(test_token_data['secret'], token)
    assert payload['iss'] == 'usr_defined_idd'


def test_decode():
    for alg, token in test_tokens.items():
        assert jwt.decode(
            test_token_data['secret'],
            token,
            alg
        ) == test_token_data['payload']


def test_decode_invalid_signature():
    for alg, token in test_tokens.items():
        token_parts = util.to_bytes(token).split(b'.')
        signature = util.b64_decode(token_parts[2]) + b'e'
        token_parts[2] = util.b64_encode(signature)
        bad_token = util.join(*token_parts)
        with pytest.raises(InvalidSignatureError):
            jwt.decode(
                test_token_data['secret'],
                util.from_bytes(bad_token),
                alg
            )


def test_decode_invalid_payload():
    token = jwt.encode(test_token_data['secret'], 'should be dict')
    with pytest.raises(RuntimeError):
        jwt.decode(test_token_data['secret'], token)
