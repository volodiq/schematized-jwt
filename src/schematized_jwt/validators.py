import time
from abc import ABC, abstractmethod

from schematized_jwt.annotations import PayloadDict, TokenTTL
from schematized_jwt.enums import TokenType
from schematized_jwt.exceptions import (
    JWTValidationExpiredError,
    JWTValidationInvalidPayload,
    JWTValidationMismatchTokenTypeError,
)


class BaseJWTPayloadValidator(ABC):
    def __init__(self, token_type: TokenType) -> None:
        self._token_type = token_type

    @abstractmethod
    def validate(self, payload: PayloadDict, token_type: TokenType) -> None:
        """
        Raises:
            - schematized_jwt.exceptions.JWTValidationError or subs: If token not valid.
        """
        ...


class TTLPayloadValidator(BaseJWTPayloadValidator):
    def __init__(self, token_ttl: TokenTTL, token_type: TokenType) -> None:
        super().__init__(token_type)
        self._token_ttl = token_ttl

    def validate(self, payload: PayloadDict, token_type: TokenType) -> None:
        if self._token_ttl is None:
            return
        if self._token_type != token_type:
            return

        try:
            exp_stamp = payload["exp"]
            if not isinstance(exp_stamp, int):
                raise JWTValidationInvalidPayload
            now_stamp = int(time.time())
            if now_stamp > exp_stamp:
                raise JWTValidationExpiredError
        except KeyError as e:
            raise JWTValidationInvalidPayload from e


class TypePayloadValidator(BaseJWTPayloadValidator):
    def validate(self, payload: PayloadDict, token_type: TokenType) -> None:
        if self._token_type != token_type:
            return

        try:
            payload_token_type = payload["type"]
            if not isinstance(payload_token_type, str):
                raise JWTValidationInvalidPayload
            if payload_token_type != token_type:
                raise JWTValidationMismatchTokenTypeError
        except KeyError as e:
            raise JWTValidationInvalidPayload from e
