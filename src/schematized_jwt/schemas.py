from pydantic import BaseModel, Field


class JWTSchema(BaseModel):
    """
    Describes the payload of the token (not including technical
    details such as exp, aud, iat, and others).
    It is used as a DTO when encoding and decoding a token.
    """

    sub: str = Field(
        ...,
        description="""
        The "sub" (subject) claim identifies the principal that is the
        subject of the JWT.  The claims in a JWT are normally statements
        about the subject.  The subject value MUST either be scoped to be
        locally unique in the context of the issuer or be globally unique.
        The processing of this claim is generally application specific.  The
        "sub" value is a case-sensitive string containing a StringOrURI
        value. 
        https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
        """,
    )
