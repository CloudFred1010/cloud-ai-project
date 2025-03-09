import requests
from fastapi import HTTPException, Header
from jose import jwt
import base64
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Keycloak Configuration
KEYCLOAK_SERVER = "http://localhost:8080/"
KEYCLOAK_REALM = "master"
KEYCLOAK_CLIENT_ID = "fastapi-client"
KEYCLOAK_CLIENT_SECRET = "vqciZUAUyJJchQJZkm1K4stgK9pS5eDA"

def get_current_user(authorization: str = Header(None)):
    """Extracts and validates the user token from the Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")

    token = parts[1]

    try:
        # Fetch Keycloak's public key dynamically
        keycloak_cert_url = f"{KEYCLOAK_SERVER}realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
        certs_response = requests.get(keycloak_cert_url)

        if certs_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch Keycloak public keys")

        certs = certs_response.json()

        # Extract the correct public key by matching 'kid' in token header
        token_headers = jwt.get_unverified_header(token)
        key_data = next((key for key in certs["keys"] if key["kid"] == token_headers["kid"]), None)

        if not key_data:
            raise HTTPException(status_code=401, detail="Invalid token: Key not found in Keycloak")

        # Convert modulus ('n') and exponent ('e') into a proper PEM-formatted RSA key
        public_key_pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + base64.b64encode(base64.b64decode(key_data["n"])).decode("utf-8")
            + "\n-----END PUBLIC KEY-----"
        )

        # Decode and validate token
        token_info = jwt.decode(
            token,
            public_key_pem,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )

        if "preferred_username" not in token_info:
            raise HTTPException(status_code=403, detail="Unauthorized access: Missing preferred_username")

        logger.info(f"User authenticated: {token_info.get('preferred_username')}")
        return token_info

    except jwt.JWTError as jwt_error:
        logger.error(f"JWT decoding error: {str(jwt_error)}")
        raise HTTPException(status_code=401, detail="Invalid token: JWT verification failed")

    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")
