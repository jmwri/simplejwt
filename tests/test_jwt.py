import pytest
import hashlib
from datetime import datetime

from simplejwt import jwt, util
from simplejwt.exception import InvalidSignatureError, InvalidHeaderError, \
    InvalidPayloadError

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
    for name, abb in jwt.registered_claims.items():
        args = {
            'secret': test_token_data['secret'],
            'payload': test_token_data['payload'],
            name: test_registered_claims[name]
        }
        token = jwt.make(**args)
        payload = jwt.decode(test_token_data['secret'], token)
        assert payload[abb] == test_registered_claims[name]


def test_jwt_registered_claims_constructor():
    for name, abb in jwt.registered_claims.items():
        args = {
            'secret': test_token_data['secret'],
            'payload': test_token_data['payload'],
            name: test_registered_claims[name]
        }
        obj = jwt.Jwt(**args)
        assert getattr(obj, name) == test_registered_claims[name]


def test_jwt_registered_claims():
    for name, abb in jwt.registered_claims.items():
        args = {
            'secret': test_token_data['secret'],
            'payload': test_token_data['payload'],
        }
        obj = jwt.Jwt(**args)
        setattr(obj, name, test_registered_claims[name])
        token = obj.encode()
        payload = jwt.decode(test_token_data['secret'], token)
        assert getattr(obj, name) == test_registered_claims[name]
        assert payload[abb] == test_registered_claims[name]


def test_jwt_precedence():
    obj = jwt.Jwt('secret', {'iss': 'usr_defined_iss'}, issuer='my_iss')
    assert obj.registered_claims['iss'] == 'usr_defined_iss'


def test_jwt_decode():
    for alg, token in test_tokens.items():
        obj = jwt.Jwt.decode(
            test_token_data['secret'],
            token,
            alg
        )
        assert obj.secret == test_token_data['secret']
        assert obj.alg == alg
        assert obj.header == {
            'type': 'JWT',
            'alg': alg
        }
        assert obj.payload == test_token_data['payload']


def test_jwt_valid():
    obj = jwt.Jwt('secret', {}, valid_from=2, valid_to=4)
    assert not obj.valid(1)
    assert obj.valid(2)
    assert obj.valid(3)
    assert obj.valid(4)
    assert not obj.valid(5)


def test_jwt_valid_current_time():
    now = int(datetime.utcnow().timestamp())
    obj = jwt.Jwt('secret', {}, valid_from=now, valid_to=now)
    assert obj.valid()
    obj = jwt.Jwt('secret', {}, valid_from=now + 1, valid_to=now + 1)
    assert not obj.valid()


def test_make_precedence():
    token = jwt.make(test_token_data['secret'], {'iss': 'usr_defined_iss'},
                     issuer='my_iss')
    payload = jwt.decode(test_token_data['secret'], token)
    assert payload['iss'] == 'usr_defined_iss'


def test_make_leaves_payload_unmodified():
    payload = {'my': 'payload'}
    jwt.make(test_token_data['secret'], payload, issuer='my_iss')
    assert payload == {'my': 'payload'}


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


def test_decode_invalid_header():
    token = jwt.encode(test_token_data['secret'], header='should be dict')
    with pytest.raises(InvalidHeaderError):
        jwt.decode(test_token_data['secret'], token)


def test_decode_invalid_json_header():
    token = jwt.encode(test_token_data['secret'], header={'valid': 'header'})
    header, payload, signature = token.split('.')
    header = str([
        '{' if k % 3 == 0 else v
        for k, v in enumerate(header)
    ])
    invalid_token = '.'.join([header, payload, signature])
    with pytest.raises(InvalidHeaderError):
        jwt.decode(test_token_data['secret'], invalid_token)


def test_decode_invalid_payload():
    token = jwt.encode(test_token_data['secret'], 'should be dict')
    with pytest.raises(InvalidPayloadError):
        jwt.decode(test_token_data['secret'], token)


def test_decode_invalid_json_payload():
    token = jwt.encode(test_token_data['secret'], payload={'valid': 'payload'})
    header, payload, signature = token.split('.')
    payload = str([
        '{' if k % 3 == 0 else v
        for k, v in enumerate(payload)
    ])
    invalid_token = '.'.join([header, payload, signature])
    with pytest.raises(InvalidPayloadError):
        jwt.decode(test_token_data['secret'], invalid_token)
