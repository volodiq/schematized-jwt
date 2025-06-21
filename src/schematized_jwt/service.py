import datetime
import time
from enum import StrEnum
from typing import Annotated, Generic, Literal, TypeVar

import jwt

from .schemas import JWTSchema

TS = TypeVar("TS", bound=JWTSchema)
type JWTEncodeAlgorithm = Literal["ES256", "HS256", "RS256", "PS256"]
type TokenTTL = Annotated[
    datetime.timedelta | None,
    """
    The validity period of the token, if None is specified, the token has no expiration date.
    """,
]
type JWTToken = Annotated[str, "Encoded JWT token."]


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


class PayloadBuilder:
    def __init__(
        self,
        access_ttl: TokenTTL,
        refresh_ttl: TokenTTL,
    ) -> None:
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl

    def _add_exp(self, payload: dict, token_type: TokenType):
        token_ttl = {
            TokenType.ACCESS: self.access_ttl,
            TokenType.REFRESH: self.refresh_ttl,
        }[token_type]
        if token_ttl:
            now = int(time.time())
            token_exp = now + token_ttl.seconds
            payload.update({"exp": token_exp})

    def _add_token_type(self, payload: dict, token_type: TokenType):
        payload.update({"type": token_type})

    def payload_build(
        self,
        payload: JWTSchema,
        token_type: TokenType,
    ) -> dict:
        payload_with_tech_data = payload.model_dump()
        self._add_exp(
            payload=payload_with_tech_data,
            token_type=token_type,
        )
        self._add_token_type(
            payload=payload_with_tech_data,
            token_type=token_type,
        )
        return payload_with_tech_data


class JWTEncoder:
    def __init__(
        self,
        payload_builder: PayloadBuilder,
        secret_key: str,
        algorithm: JWTEncodeAlgorithm,
    ) -> None:
        self.payload_builder = payload_builder
        self.secret_key = secret_key
        self.algorithm = algorithm

    def _base_encode(self, payload, token_type: TokenType) -> JWTToken:
        payload_with_tech_data = self.payload_builder.payload_build(
            payload=payload,
            token_type=token_type,
        )
        return jwt.encode(
            payload=payload_with_tech_data,
            key=self.secret_key,
            algorithm=self.algorithm,
        )

    def encode_access(self, payload: JWTSchema) -> JWTToken:
        return self._base_encode(payload=payload, token_type=TokenType.ACCESS)

    def encode_refresh(self, payload: JWTSchema) -> JWTToken:
        return self._base_encode(payload=payload, token_type=TokenType.REFRESH)


class JWTDecoder:
    def __init__(
        self,
        secret_key: str,
        algorithm: JWTEncodeAlgorithm,
    ) -> None:
        self.secret_key = secret_key
        self.algorithm = algorithm

    def decode(self, token: JWTToken) -> dict:
        return jwt.decode(
            jwt=token,
            key=self.secret_key,
            algorithms=self.algorithm,
        )


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
    ] = NotImplemented
    algorithm: JWTEncodeAlgorithm = "HS256"

    # Tokens TTL
    access_ttl: TokenTTL = datetime.timedelta(minutes=30)
    refresh_ttl: TokenTTL = datetime.timedelta(days=7)

    @classmethod
    def get_payload_builder(cls) -> PayloadBuilder:
        return PayloadBuilder(
            access_ttl=cls.access_ttl,
            refresh_ttl=cls.refresh_ttl,
        )

    @classmethod
    def get_jwt_encoder(cls) -> JWTEncoder:
        return JWTEncoder(
            payload_builder=cls.get_payload_builder(),
            secret_key=cls.secret_key,
            algorithm=cls.algorithm,
        )

    @classmethod
    def get_jwt_decoder(cls) -> JWTDecoder:
        return JWTDecoder(
            secret_key=cls.secret_key,
            algorithm=cls.algorithm,
        )

    @classmethod
    def encode_access(cls, payload: TS) -> JWTToken:
        return cls.get_jwt_encoder().encode_access(payload)

    @classmethod
    def encode_refresh(cls, payload: TS) -> JWTToken:
        return cls.get_jwt_encoder().encode_refresh(payload)

    @classmethod
    def decode_access(cls, token: JWTToken) -> TS:
        payload = cls.get_jwt_decoder().decode(token)
        # TODO Add try except
        # TODO Add validate token payload
        return cls.token_schema.model_validate(payload)

    @classmethod
    def decode_refresh(cls, token: JWTToken) -> TS:
        payload = cls.get_jwt_decoder().decode(token)
        # TODO Add try except
        # TODO Add validate token payload
        return cls.token_schema.model_validate(payload)
