import datetime
import time
from abc import ABC
from enum import StrEnum
from typing import Annotated, Literal

import jwt
from pydantic import BaseModel, ValidationError

from schematized_jwt import exceptions as exc

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
        payload: BaseModel,
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

    def _base_encode(self, payload: BaseModel, token_type: TokenType) -> JWTToken:
        payload_with_tech_data = self.payload_builder.payload_build(
            payload=payload,
            token_type=token_type,
        )
        return jwt.encode(
            payload=payload_with_tech_data,
            key=self.secret_key,
            algorithm=self.algorithm,
        )

    def encode_access(self, payload: BaseModel) -> JWTToken:
        return self._base_encode(payload=payload, token_type=TokenType.ACCESS)

    def encode_refresh(self, payload: BaseModel) -> JWTToken:
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
            options={"verify_exp": True},
        )


class PayloadValidator:
    @classmethod
    def _validate_type(cls, payload: dict, token_type: TokenType) -> None:
        payload_token_type = payload.get("type")
        if payload_token_type != token_type:
            raise exc.JWTInvalidTokenType

    @classmethod
    def validate(cls, payload: dict, token_type: TokenType) -> None:
        cls._validate_type(payload=payload, token_type=token_type)


class BaseJWTService(ABC):
    """
    Base JWT service class that provides common JWT functionality.
    This is a generic class that works with different JWT schema types
    (subclasses of JWTSchema), specified by the TS parameter.

    Usage example:
    ```
    class JWTService(BaseJWTService):
        class TokenPayload(BaseJWTService):
            sub: str

        secret_key = config.secret_key


    access = JWTService.encode_access(JWTService.TokenPayload(sub=uuid.uuid4().hex))
    decoded: JWTService.TokenPayload = JWTService.decode_access(access)
    ```
    """

    class TokenPayload(ABC, BaseModel):
        """
        Describes the payload of access token (not including technical
        details such as exp, aud, iat, and others).
        """

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
    def get_payload_validator(cls) -> type[PayloadValidator]:
        return PayloadValidator

    @classmethod
    def encode_access(cls, payload: TokenPayload) -> JWTToken:
        return cls.get_jwt_encoder().encode_access(payload)

    @classmethod
    def encode_refresh(cls, payload: TokenPayload) -> JWTToken:
        return cls.get_jwt_encoder().encode_refresh(payload)

    @classmethod
    def _decode_token(cls, token: JWTToken, token_type: TokenType) -> TokenPayload:
        try:
            payload = cls.get_jwt_decoder().decode(token)
        except jwt.ExpiredSignatureError:
            raise exc.JWTExpiredError
        except jwt.PyJWTError:
            raise exc.JWTInvalidError

        cls.get_payload_validator().validate(payload, token_type=token_type)

        try:
            return cls.TokenPayload.model_validate(payload)
        except ValidationError as e:
            raise exc.JWTInvalidPayloadError from e

    @classmethod
    def decode_access(cls, token: JWTToken) -> TokenPayload:
        return cls._decode_token(token, TokenType.ACCESS)

    @classmethod
    def decode_refresh(cls, token: JWTToken) -> TokenPayload:
        return cls._decode_token(token, TokenType.REFRESH)
