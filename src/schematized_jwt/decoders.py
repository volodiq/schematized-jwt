from abc import ABC, abstractmethod

import jwt

from schematized_jwt.annotations import JWTEncodeAlgorithm, JWTToken, PayloadDict
from schematized_jwt.exceptions import JWTDecodeInvalidError


class BaseJWTDecoder(ABC):
    def __init__(
        self,
        secret_key: str,
        algorithm: JWTEncodeAlgorithm,
    ) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm

    @abstractmethod
    def decode(self, token: JWTToken) -> PayloadDict:
        """
        Raises:
            - schematized_jwt.exceptions.JWTDecodeInvalidError: Token is invalid (
                not readable or invalid signature
            ).
        """
        ...


class PyJWTDecoder(BaseJWTDecoder):
    def decode(self, token: JWTToken) -> PayloadDict:
        try:
            return jwt.decode(
                jwt=token,
                key=self._secret_key,
                algorithms=self._algorithm,
                options={
                    "verify_signature": False,
                },
            )
        except jwt.exceptions.PyJWTError as e:
            raise JWTDecodeInvalidError from e
