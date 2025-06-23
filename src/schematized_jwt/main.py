import datetime
from functools import wraps
from typing import Any, Callable, Concatenate, Generic, Iterable, ParamSpec, TypeVar

from schematized_jwt.annotations import JWTEncodeAlgorithm, JWTToken
from schematized_jwt.decoders import BaseJWTDecoder, PyJWTDecoder
from schematized_jwt.encoders import BaseJWTEncoder, PyJWTEncoder
from schematized_jwt.enums import TokenType
from schematized_jwt.extenders import BaseJWTPayloadExtender, TTLPayloadExtender
from schematized_jwt.validators import BaseJWTPayloadValidator, TTLPayloadValidator

APP = ParamSpec("APP")
APM = TypeVar("APM")

RPP = ParamSpec("RPP")
RPM = TypeVar("RPM")


class BaseJWTService(Generic[APP, APM, RPM, RPP]):
    @staticmethod
    def add_access_signature(method):
        @wraps(method)
        def inner(method) -> Callable[Concatenate[..., APP], JWTToken]:
            return method

        return inner(method)

    @staticmethod
    def add_refresh_signature(method):
        @wraps(method)
        def inner(method) -> Callable[Concatenate[..., RPP], JWTToken]:
            return method

        return inner(method)

    def __init__(
        self,
        access_payload: Callable[APP, APM],
        refresh_payload: Callable[RPP, RPM],
        secret_key: str,
        algorithm: JWTEncodeAlgorithm = "HS256",
        token_decoder: type[BaseJWTDecoder] = PyJWTDecoder,
        token_encoder: type[BaseJWTEncoder] = PyJWTEncoder,
        payload_extenders: Iterable[BaseJWTPayloadExtender] = (
            TTLPayloadExtender(
                token_ttl=datetime.timedelta(minutes=15), token_type=TokenType.ACCESS
            ),
            TTLPayloadExtender(
                token_ttl=datetime.timedelta(days=7), token_type=TokenType.REFRESH
            ),
        ),
        payload_validators: Iterable[BaseJWTPayloadValidator] = (
            TTLPayloadValidator(
                token_ttl=datetime.timedelta(minutes=15), token_type=TokenType.ACCESS
            ),
            TTLPayloadValidator(
                token_ttl=datetime.timedelta(days=7), token_type=TokenType.REFRESH
            ),
        ),
    ) -> None:
        self.access_payload: APM = access_payload  # type: ignore
        self.refresh_payload: RPM = refresh_payload  # type: ignore

        self.token_encoder = token_encoder(secret_key=secret_key, algorithm=algorithm)
        self.token_decoder = token_decoder(secret_key=secret_key, algorithm=algorithm)

        self.payload_extenders = payload_extenders
        self.payload_validators = payload_validators

    @add_access_signature
    def encode_access(self, **kwargs: Any) -> JWTToken:
        payload = self.access_payload.model_validate(kwargs)  # type: ignore
        payload_dumped = payload.model_dump(mode="json")
        for payload_extender in self.payload_extenders:
            payload_dumped = payload_extender.extend(
                payload=payload_dumped,
                token_type=TokenType.ACCESS,
            )
        return self.token_encoder.encode(payload_dumped)

    def decode_access(self, token: str) -> APM:
        decoded = self.token_decoder.decode(token)
        decoded_payload = self.token_decoder.decode(token)
        for validator in self.payload_validators:
            validator.validate(payload=decoded_payload, token_type=TokenType.ACCESS)
        return self.access_payload.model_validate(decoded)  # type: ignore

    @add_refresh_signature
    def encode_refresh(self, **kwargs: Any) -> JWTToken:
        payload = self.refresh_payload.model_validate(kwargs)  # type: ignore
        payload_dumped = payload.model_dump(mode="json")
        for payload_extender in self.payload_extenders:
            payload_dumped = payload_extender.extend(
                payload=payload_dumped,
                token_type=TokenType.REFRESH,
            )
        return self.token_encoder.encode(payload_dumped)

    def decode_refresh(self, token: str) -> RPM:
        decoded_payload = self.token_decoder.decode(token)
        for validator in self.payload_validators:
            validator.validate(payload=decoded_payload, token_type=TokenType.REFRESH)
        return self.refresh_payload.model_validate(decoded_payload)  # type: ignore
