class SchematizedJWTError(Exception):
    """Any errors while working with JWT."""


class JWTInvalidError(SchematizedJWTError):
    """Token is invalid."""


class JWTInvalidPayloadError(SchematizedJWTError):
    """Specified schema for JWT and payload does not match."""


class JWTValidationError(SchematizedJWTError):
    """Any errors while validate JWT payload."""


class JWTExpiredError(JWTValidationError):
    """TTL of JWT has been expired."""


class JWTInvalidTokenType(JWTValidationError):
    """The type of JWT in the payload does not match."""
