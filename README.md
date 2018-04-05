# simplejwt

[![PyPI version](https://badge.fury.io/py/simplejwt.svg)](https://badge.fury.io/py/simplejwt)
[![Build Status](https://travis-ci.org/jmwri/simplejwt.svg?branch=master)](https://travis-ci.org/jmwri/simplejwt)
[![Test Coverage](https://api.codeclimate.com/v1/badges/740ea32cb00bd8c3520a/test_coverage)](https://codeclimate.com/github/jmwri/simplejwt/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/740ea32cb00bd8c3520a/maintainability)](https://codeclimate.com/github/jmwri/simplejwt/maintainability)

A dead simple JWT library.

# Supported algorithms

* HS256
* HS384
* HS512

# Usage
## Encode
Returns a new token.

```
from simplejwt import encode
token = encode('secret', {'my_payload': 'some_data'}, 'HS256')
# eyJ0eXBlIjogIkpXVCIsICJhbGciOiAiSFMyNTYifQ.eyJteV9wYXlsb2FkIjogInNvbWVfZGF0YSJ9.BXAs5tYkARpGHhegb8g8bfj8KhjFUTTjdEf81Ma1VhY
```

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `secret` | `str` | *N/A* | The secret used to create the token. |
| `payload` | `dict` | *N/A* | The payload data contained within the token. |
| `alg` | `int` | `HS256` | The algorithm to use to create the token. |

## Make
Returns a new token. This function has arguments for registered claims as specified in [rfc7519](https://tools.ietf.org/html/rfc7519#section-4.1).

Any registered claims provided in the payload will take precedence over any provided as arguments. 

```
from simplejwt import make
token = make('secret', {'my_payload': 'some_data'}, 'HS256', issuer='acme', valid_to=1234567)
# eyJ0eXBlIjogIkpXVCIsICJhbGciOiAiSFMyNTYifQ.eyJteV9wYXlsb2FkIjogInNvbWVfZGF0YSIsICJpc3MiOiAiYWNtZSIsICJleHAiOiAxMjM0NTY3fQ.Nr5IADzsOhlzjxnghquBrRwewg10srDHu__-HN7GGGA
```

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `secret` | `str` | *N/A* | The secret used to create the token. |
| `payload` | `dict` | *N/A* | The payload data contained within the token. |
| `alg` | `int` | `HS256` | The algorithm to use to create the token. |
| `issuer` | `str` | `None` | The issuer of the token. |
| `subject` | `str` | `None` | The subject of the token. |
| `audience` | `str` | `None` | The audience of the token. |
| `valid_to` | `int` | `None` | The expiry date of the token as a timestamp. |
| `valid_from` | `int` | `None` | The date the token is valid from as a timestamp. |
| `issued_at` | `int` | `None` | The date the token was issued as a timestamp. |
| `id` | `str` | `None` | The id of the token. |

## Decode
Returns the payload from a token.

```
from simplejwt import encode, decode
token = encode('secret', {'my_payload': 'some_data'}, 'HS256')
payload = decode('secret', token, 'HS256')
# {'my_payload': 'some_data'}
```

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `secret` | `str` | *N/A* | The secret used to decode the token. |
| `payload` | `dict` | *N/A* | The token to decode. |
| `alg` | `int` | `HS256` | The algorithm to use to create the token. |

# Running tests
## Install the package with test dependencies
`pip install -e ".[test]"`

## Run tox
`tox`
