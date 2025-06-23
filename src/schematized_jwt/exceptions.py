class SchematizedJWTError(Exception):
    """Any errors while working with JWT."""


# Decode


class JWTDecodeInvalidError(SchematizedJWTError):
    """Token is invalid."""


# Encode


class JWTInvalidPayloadError(SchematizedJWTError):
    """Specified schema for JWT and payload does not match."""


# Decoded validation


class JWTValidationError(SchematizedJWTError):
    """Any errors while validate JWT payload."""


class JWTValidationInvalidPayload(JWTValidationError):
    """Decoded payload from token is invalid."""


class JWTValidationExpiredError(JWTValidationError):
    """TTL of JWT has been expired."""


# class JWTInvalidTokenType(JWTValidationError):
#     """The type of JWT in the payload does not match."""
