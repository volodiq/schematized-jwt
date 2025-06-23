import time
from abc import ABC, abstractmethod

from schematized_jwt.annotations import PayloadDict, TokenTTL
from schematized_jwt.enums import TokenType
from schematized_jwt.exceptions import (
    JWTValidationExpiredError,
    JWTValidationInvalidPayload,
)


class BaseJWTPayloadValidator(ABC):
    @abstractmethod
    def validate(self, payload: PayloadDict, token_type: TokenType) -> None:
        """
        Raises:
            - schematized_jwt.exceptions.JWTValidationError or subs: If token not valid.
        """
        ...


class TTLPayloadValidator(BaseJWTPayloadValidator):
    def __init__(self, token_ttl: TokenTTL, token_type: TokenType) -> None:
        self._token_ttl = token_ttl
        self._token_type = token_type

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
