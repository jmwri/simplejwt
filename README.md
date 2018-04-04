# simplejwt

[![PyPI version](https://badge.fury.io/py/simplejwt.svg)](https://badge.fury.io/py/simplejwt)
[![Build Status](https://travis-ci.org/jmwri/simplejwt.svg?branch=master)](https://travis-ci.org/jmwri/simplejwt)
[![Test Coverage](https://api.codeclimate.com/v1/badges/740ea32cb00bd8c3520a/test_coverage)](https://codeclimate.com/github/jmwri/simplejwt/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/740ea32cb00bd8c3520a/maintainability)](https://codeclimate.com/github/jmwri/simplejwt/maintainability)

A dead simple JWT library.

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
