from fastapi import HTTPException
from jose import jwt, JWTError
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
import requests

KEYCLOAK_SERVER = "http://localhost:8080"
KEYCLOAK_REALM = "master"
ALGORITHM = "RS256"
AUDIENCE = "fastapi-client"
ISSUER = f"{KEYCLOAK_SERVER}/realms/{KEYCLOAK_REALM}"

def get_keycloak_public_key(token):
    headers = jwt.get_unverified_header(token)
    kid = headers.get('kid')
    jwks_url = f"{KEYCLOAK_SERVER}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
    jwks = requests.get(jwks_url).json()

    key = next((k for k in jwks['keys'] if k['kid'] == kid), None)
    if not key:
        raise HTTPException(status_code=401, detail="Public key not found")

    e = int.from_bytes(base64url_decode(key['e'].encode('utf-8')), 'big')
    n = int.from_bytes(base64url_decode(key['n'].encode('utf-8')), 'big')
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    return public_key

async def get_current_user(token: str):
    try:
        public_key = get_keycloak_public_key(token)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"verify_aud": True}
        )
        username = payload.get("preferred_username")
        if not username:
            raise HTTPException(status_code=401, detail="Missing username in token.")
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
