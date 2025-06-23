import datetime
from typing import Annotated, Literal

type JWTToken = Annotated[str, "Encoded JWT token."]
type JWTEncodeAlgorithm = Literal["ES256", "HS256", "RS256", "PS256"]
type TokenTTL = Annotated[
    datetime.timedelta | None,
    """
    The validity period of the token, if None is specified, the token has no expiration date.
    """,
]
type JSONType = None | int | str | bool | list[JSONType] | dict[str, JSONType]
type PayloadDict = dict[str, JSONType]
