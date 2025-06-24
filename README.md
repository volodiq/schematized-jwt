A project for encoding and decoding JWT tokens using Pydantic schemas.
### Install
```
pip install schematized-jwt
uv add schematized-jwt
poetry add schematized-jwt
```

### Usage example:
```python
from pydantic import BaseModel

from schematized_jwt import BaseJWTService


class AccessPayload(BaseModel):
    """
    Access token payload (does not include exp, iat and other service fields)
    """
    oid: str
    name: str


class RefreshPayload(BaseModel):
    """
    Refresh token payload (does not include exp, iat and other service fields)
    """
    oid: str


JWTService = BaseJWTService(
    access_payload=AccessPayload,
    refresh_payload=RefreshPayload,
    secret_key="your_strong_secret",
)

# Access
access = JWTService.encode_access(oid="123", name="Bobr") # There's an auto-complement from the IDE and a type checker!
print(f"{access=}")
decoded_a = JWTService.decode_access(access) # Here you get a payload in the form of a previously specified payload schema for access tokens!
print(f"{decoded_a=}")


# Refresh
refresh = JWTService.encode_refresh(oid="123") # There's an auto-complement from the IDE and a type checker!
print(f"{refresh=}")
decoded_r = JWTService.decode_refresh(refresh) # Here you get a payload in the form of a previously specified schema for refresh tokens!
print(f"{decoded_r=}")
```
