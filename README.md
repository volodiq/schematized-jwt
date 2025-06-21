A project for encoding and decoding JWT tokens using Pydantic schemas.

# Usage example:
```python
class JWTService(BaseJWTService[JWTSchema]):
    payload_schema = JWTSchema
    secret_key = config.secret_key


simple_jwt_access = JWTService.encode_access(JWTSchema(sub=uuid.uuid4().hex))
simple_jwt_decoded = JWTService.decode_access(access)


class PhoneJWTSchema(JWTSchema):
    phone: str

class PhoneJWTService(BaseJWTService[PhoneJWTSchema]):
    payload_schema = PhoneJWTSchema
    secret_key = config.secret_key


phone_jwt_access = JWTService.encode_access(JWTSchema(sub=uuid.uuid4().hex, phone="+123123123"))
phone_jwt_decoded = JWTService.decode_access(access)
```