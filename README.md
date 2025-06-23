A project for encoding and decoding JWT tokens using Pydantic schemas.

# Usage example:
```python
from pydantic import BaseModel

from schematized_jwt import BaseJWTService


class AccessPayload(BaseModel):
    oid: str
    name: str


class RefreshPayload(BaseModel):
    oid: str


JWTService = BaseJWTService(
    access_payload=AccessPayload,
    refresh_payload=RefreshPayload,
    secret_key="your_strong_secret",
)

# Access
access = JWTService.encode_access(oid="123", name="Bobr")
print(f"{access=}")
decoded_a = JWTService.decode_access(access)
print(f"{decoded_a=}")


# Refresh
refresh = JWTService.encode_refresh(oid="123")
print(f"{refresh=}")
decoded_r = JWTService.decode_refresh(refresh)
print(f"{decoded_r=}")
```