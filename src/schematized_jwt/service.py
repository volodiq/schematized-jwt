import datetime
from typing import Annotated, Generic, Literal, TypeVar

from .schemas import JWTSchema

TS = TypeVar("TS", bound=JWTSchema)
type JWTEncodeAlgorithm = Literal["ES256", "HS256", "RS256", "PS256"]
type TokenTTL = Annotated[
    datetime.timedelta | None,
    """
    The validity period of the token, if None is specified, the token has no expiration date.
    """,
]


class BaseJWTService(Generic[TS]):
    """
    Base JWT service class that provides common JWT functionality.
    This is a generic class that works with different JWT schema types
    (subclasses of JWTSchema), specified by the TS parameter.

    Usage example:
    ```
    ```
    """

    # TODO: Add usage example to docstrings.

    token_schema: type[TS]

    # Base configuration
    secret_key: Annotated[
        str,
        "The secret key used for signing and verifying JWT tokens.",
    ]
    algorithm: JWTEncodeAlgorithm = "HS256"

    # Tokens TTL
    access_ttl: TokenTTL = datetime.timedelta(minutes=30)
    refresh_ttl: TokenTTL = datetime.timedelta(days=7)
