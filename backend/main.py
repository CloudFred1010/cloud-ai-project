from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from auth import get_current_user
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI App
app = FastAPI(
    title="Cloud AI Project API",
    description="FastAPI service with Keycloak authentication",
    version="1.0.0",
)

# CORS Middleware (Update with actual frontend domains in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "Cloud AI Project Running Successfully"}

@app.get("/secure-data")
def secure_data(user=Depends(get_current_user)):
    return {"message": "Secure data accessed", "user": user}

@app.get("/health")
def health_check():
    """Health check endpoint to monitor service availability."""
    return {"status": "API is healthy"}

@app.get("/protected-endpoint")
def protected_route(user=Depends(get_current_user)):
    """This endpoint requires authentication via Keycloak."""
    return {
        "message": "Protected resource accessed successfully",
        "username": user.get("preferred_username"),
        "email": user.get("email"),
    }

# OpenAPI Docs
@app.get("/docs", include_in_schema=False)
def get_swagger_ui():
    return app.openapi()

@app.get("/openapi.json", include_in_schema=False)
def get_openapi_json():
    return app.openapi()
