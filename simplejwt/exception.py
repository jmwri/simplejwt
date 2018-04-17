class InvalidSignatureError(Exception):
    """
    Thrown when bad a signature does not match when decoding a token.
    """
    pass


class InvalidHeaderError(Exception):
    """
    Thrown when the provided header is invalid.
    """
    pass


class InvalidPayloadError(Exception):
    """
    Thrown when the provided payload is invalid.
    """
    pass
