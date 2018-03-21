from simplejwt import jwt
import pytest
import hashlib

test_tokens = {
    'HS256': 'eyJ0eXBlIjogIkpXVCIsICJhbGciOiAiSFMyNTYifQ.'
             'eyJ0ZXN0aW5nIjogdHJ1ZX0.'
             'rAuMC7c8hCaBZPmGm-n-23gR3Pa_qvdPUr0-WuDJBpc'
}


def test_b64_encode():
    assert jwt.b64_encode(b'test') == b'dGVzdA'


def test_to_bytes():
    assert jwt.to_bytes('test') == b'test'
    assert jwt.to_bytes(b'test') == b'test'


def test_from_bytes():
    assert jwt.from_bytes('test') == 'test'
    assert jwt.from_bytes(b'test') == 'test'


def test_join():
    assert jwt.join(b'a', b'b', b'c', b'd') == b'a.b.c.d'


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
