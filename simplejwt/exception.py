class InvalidTokenError(Exception):
    """
    A child of this error will be raised when there is an issue with the token.
    """
    pass


class InvalidSignatureError(InvalidTokenError):
    """
    Thrown when bad a signature does not match when decoding a token.
    """
    pass


class InvalidHeaderError(InvalidTokenError):
    """
    Thrown when the provided header is invalid.
    """
    pass


class InvalidPayloadError(InvalidTokenError):
    """
    Thrown when the provided payload is invalid.
    """
    pass
