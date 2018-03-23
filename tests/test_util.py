from simplejwt import util


def test_b64_encode():
    assert util.b64_encode(b'test') == b'dGVzdA'


def test_to_bytes():
    assert util.to_bytes('test') == b'test'
    assert util.to_bytes(b'test') == b'test'


def test_from_bytes():
    assert util.from_bytes('test') == 'test'
    assert util.from_bytes(b'test') == 'test'


def test_join():
    assert util.join(b'a', b'b', b'c', b'd') == b'a.b.c.d'
