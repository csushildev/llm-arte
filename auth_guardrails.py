"""
Authentication and Authorization Guardrails
Validates API keys and user permissions.
Covers: API key validation, user roles, access control.
"""
import os
from dotenv import load_dotenv
from functools import lru_cache

load_dotenv()

# ============================================================
# AUTHORIZED API KEYS (In production, use a database)
# ============================================================
AUTHORIZED_KEYS = {
    "demo_key_001": {
        "user": "demo_user",
        "role": "user",
        "active": True
    },
    "admin_key_001": {
        "user": "admin",
        "role": "admin",
        "active": True
    }
}

# ============================================================
# ROLE-BASED PERMISSIONS
# ============================================================
ROLE_PERMISSIONS = {
    "user": [
        "generate_prompt",
        "view_response"
    ],
    "admin": [
        "generate_prompt",
        "view_response",
        "view_logs",
        "reset_limits"
    ],
    "guest": []
}

# ============================================================
# VALIDATE API KEY
# ============================================================
@lru_cache(maxsize=128)
def validate_api_key(api_key: str) -> dict:
    """
    Validate API key.
    Returns:
        Dictionary with valid, user, role, message
    """
    if not api_key:
        return {
            "valid": False,
            "user": None,
            "role": None,
            "message": "API key is required."
        }
    
    if api_key not in AUTHORIZED_KEYS:
        return {
            "valid": False,
            "user": None,
            "role": None,
            "message": "Invalid or unknown API key."
        }
    
    key_data = AUTHORIZED_KEYS[api_key]
    
    if not key_data.get("active", False):
        return {
            "valid": False,
            "user": key_data["user"],
            "role": key_data["role"],
            "message": "API key is inactive or revoked."
        }
    
    return {
        "valid": True,
        "user": key_data["user"],
        "role": key_data["role"],
        "message": "API key is valid."
    }

# ============================================================
# CHECK PERMISSION
# ============================================================
def check_permission(
    api_key: str,
    required_permission: str
) -> dict:
    """
    Check if API key has required permission.
    Args:
        api_key: The API key to validate
        required_permission: Permission to check (e.g., "generate_prompt")
    Returns:
        Dictionary with allowed, user, role, message
    """
    validation = validate_api_key(api_key)
    
    if not validation["valid"]:
        return {
            "allowed": False,
            "category": "AUTH_INVALID_KEY",
            "user": None,
            "role": None,
            "message": validation["message"]
        }
    
    role = validation["role"]
    permissions = ROLE_PERMISSIONS.get(role, [])
    
    if required_permission not in permissions:
        return {
            "allowed": False,
            "category": "AUTH_INSUFFICIENT_PERMISSION",
            "user": validation["user"],
            "role": role,
            "message": (
                f"Role '{role}' does not have permission: "
                f"'{required_permission}'"
            )
        }
    
    return {
        "allowed": True,
        "category": "AUTH_VALID",
        "user": validation["user"],
        "role": role,
        "message": "Authorization successful."
    }

# ============================================================
# AUTH GUARDRAIL (for FastAPI integration)
# ============================================================
def check_auth_guardrail(
    api_key: str,
    required_permission: str = "generate_prompt"
) -> dict:
    """
    Main auth guardrail check.
    """
    return check_permission(api_key, required_permission)
