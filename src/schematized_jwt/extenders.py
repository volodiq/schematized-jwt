import copy
import time
from abc import ABC, abstractmethod

from schematized_jwt.annotations import PayloadDict, TokenTTL
from schematized_jwt.enums import TokenType


class BaseJWTPayloadExtender(ABC):
    def __init__(
        self,
        token_type: TokenType,
    ) -> None:
        self._token_type = token_type

    @abstractmethod
    def extend(self, payload: PayloadDict, token_type: TokenType) -> PayloadDict: ...


class TTLPayloadExtender(BaseJWTPayloadExtender):
    def __init__(self, token_type: TokenType, token_ttl: TokenTTL) -> None:
        super().__init__(token_type)
        self._token_ttl = token_ttl

    def extend(self, payload: PayloadDict, token_type: TokenType) -> PayloadDict:
        extended_payload = copy.deepcopy(payload)

        if token_type != self._token_type:
            return extended_payload

        if self._token_ttl is None:
            return extended_payload

        now_time = int(time.time())
        exp_time = now_time + int(self._token_ttl.total_seconds())
        extended_payload.update({"exp": exp_time})

        return extended_payload


class TypePayloadExtender(BaseJWTPayloadExtender):
    def extend(self, payload: PayloadDict, token_type: TokenType) -> PayloadDict:
        extended_payload = copy.deepcopy(payload)
        if self._token_type != token_type:
            return extended_payload
        extended_payload.update({"type": token_type})
        return extended_payload
