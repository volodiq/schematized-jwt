from abc import ABC, abstractmethod

import jwt

from schematized_jwt.annotations import JWTEncodeAlgorithm, JWTToken, PayloadDict


class BaseJWTEncoder(ABC):
    def __init__(
        self,
        secret_key: str,
        algorithm: JWTEncodeAlgorithm,
    ) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm

    @abstractmethod
    def encode(self, payload: PayloadDict) -> JWTToken: ...


class PyJWTEncoder(BaseJWTEncoder):
    def encode(self, payload: PayloadDict) -> JWTToken:
        return jwt.encode(
            payload=payload,
            key=self._secret_key,
            algorithm=self._algorithm,
        )
