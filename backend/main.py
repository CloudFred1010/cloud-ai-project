from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from keycloak import KeycloakOpenID
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Keycloak Configuration with validation
KEYCLOAK_SERVER = os.getenv("KEYCLOAK_SERVER", "http://keycloak-a:8080/")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "fastapi-client")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "myrealm")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "mysecret")

if not all([KEYCLOAK_SERVER, KEYCLOAK_CLIENT_ID, KEYCLOAK_REALM, KEYCLOAK_CLIENT_SECRET]):
    logger.error("❌ Missing required Keycloak environment variables!")

try:
    keycloak_openid = KeycloakOpenID(
        server_url=KEYCLOAK_SERVER,
        client_id=KEYCLOAK_CLIENT_ID,
        realm_name=KEYCLOAK_REALM,
        client_secret_key=KEYCLOAK_CLIENT_SECRET,
    )
except Exception as e:
    logger.error(f"❌ Keycloak configuration error: {str(e)}")
    raise SystemExit("Exiting due to Keycloak configuration error.")

# CORS Middleware to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_current_user(authorization: str = Header(None)):
    """Extracts and validates the user token from the Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="❌ Authorization header missing")

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="❌ Invalid Authorization header format")

    token = parts[1]
    
    try:
        user_info = keycloak_openid.introspect(token)
        if not user_info.get("active"):
            raise HTTPException(status_code=401, detail="❌ Token is inactive or expired")

        logger.info(f"✅ User authenticated: {user_info.get('preferred_username')}")
        return user_info

    except Exception as e:
        logger.error(f"❌ Token validation error: {str(e)}")
        raise HTTPException(status_code=401, detail="❌ Invalid token")

@app.get("/")
def home():
    return {"message": "🚀 Cloud AI Project Running Successfully"}

@app.get("/secure-data")
def secure_data(user=Depends(get_current_user)):
    return {"message": "🔒 Secure data accessed!", "user": user}

@app.get("/health")
def health_check():
    """Health check endpoint to monitor service availability."""
    return {"status": "✅ API is healthy", "keycloak": KEYCLOAK_SERVER}
