import pytest
import hashlib

from simplejwt import jwt
from simplejwt.exception import InvalidSignatureError

test_tokens = {
    'HS256': 'eyJ0eXBlIjogIkpXVCIsICJhbGciOiAiSFMyNTYifQ.'
             'eyJ0ZXN0aW5nIjogdHJ1ZX0.'
             'rAuMC7c8hCaBZPmGm-n-23gR3Pa_qvdPUr0-WuDJBpc'
}


def test_get_algorithm_hs256():
    assert jwt.get_algorithm('HS256') is hashlib.sha256


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


def test_decode():
    token_data = {
        'secret': 'super_secret',
        'payload': {
            'testing': True
        }
    }
    for alg, token in test_tokens.items():
        assert jwt.decode(
            token_data['secret'],
            token,
            alg
        ) == token_data['payload']


def test_decode_invalid_signature():
    token_data = {
        'secret': 'super_secret',
        'payload': {
            'testing': True
        }
    }
    for alg, token in test_tokens.items():
        with pytest.raises(InvalidSignatureError):
            jwt.decode(
                token_data['secret'],
                token + 'extra',
                alg
            )


def test_decode_invalid_payload():
    token_data = {
        'secret': 'super_secret',
        'payload': 'should be dict'
    }
    token = jwt.encode(token_data['secret'], token_data['payload'])
    with pytest.raises(RuntimeError):
        jwt.decode(token_data['secret'], token)
