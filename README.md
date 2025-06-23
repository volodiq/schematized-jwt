A project for encoding and decoding JWT tokens using Pydantic schemas.

# Usage example:
```python

# Service for JWT only with sub
class JWTService(BaseJWTService):
    class TokenPayload(BaseJWTService):
        """
        Describes the payload of access token (not including technical
        details such as exp, aud, iat, and others).
        """
        sub: str

    secret_key = config.secret_key

access = JWTService.encode_access(JWTService.TokenPayload(sub=uuid.uuid4().hex))
decoded: JWTService.TokenPayload = JWTService.decode_access(access)

# Another service, with sub and phone in payload
class PhoneJWTService(BaseJWTService):
    class TokenPayload(BaseJWTService):
        sub: str
        phone: str
        # Everything works as for the usual Pydantic
        # model - e.g you can use PhoneNumber from  pydantic_extra_types.phone_numbers


    secret_key = config.secret_key

access = PhoneJWTService.encode_access(PhoneJWTService.TokenPayload(sub=uuid.uuid4().hex, phone="+123124123"))
decoded: PhoneJWTService.TokenPayload = PhoneJWTService.decode_access(access)
```