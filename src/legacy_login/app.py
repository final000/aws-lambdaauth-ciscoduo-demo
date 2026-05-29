"""
Demo 6: Legacy Username/Password Login Lambda.

Accepts POST /legacy/login with JSON body {"username": "...", "password": "..."}.
Verifies credentials against a simulated legacy auth API, then issues an HS256 JWT.

In a real scenario, replace `verify_with_legacy_api()` with an HTTP call to
the customer's actual authentication endpoint.
"""

import os
import json
import time
import uuid
import hmac
import hashlib
import base64


# ---- Config ----
JWT_SECRET = os.environ.get("JWT_SECRET", "")
TOKEN_EXPIRY_SECONDS = int(os.environ.get("TOKEN_EXPIRY_SECONDS", "3600"))  # default 1 hour


# ---- Simulated Legacy Auth API ----
# In production, this would be an HTTP call to the customer's existing auth service.
# e.g., requests.post("https://legacy.internal/api/authenticate", json={...})
LEGACY_USERS = {
    "demo_user": {"password": "demo_pass", "email": "demo@example.com", "name": "Demo User"},
    "test_user": {"password": "test_pass", "email": "test@example.com", "name": "Test User"},
    "admin": {"password": "admin123", "email": "admin@example.com", "name": "Admin User"},
}


def verify_with_legacy_api(username, password):
    """
    Simulate calling a legacy authentication API.

    Replace this function with your actual HTTP call, e.g.:

        response = requests.post(
            "https://legacy-auth.internal/api/v1/authenticate",
            json={"username": username, "password": password},
            timeout=5,
        )
        if response.status_code == 200:
            return response.json()  # user attributes
        return None

    Returns user attributes dict on success, None on failure.
    """
    user = LEGACY_USERS.get(username)
    if user and user["password"] == password:
        # Return user attributes (everything except password)
        return {"email": user["email"], "name": user["name"]}
    return None


# ---- Lambda Handler ----

def handler(event, context):
    """Main Lambda handler for POST /legacy/login."""
    method = event.get("httpMethod", "")
    path = event.get("path", "")

    if method == "POST" and "/legacy/login" in path:
        return handle_login(event)
    else:
        return response(404, {"error": "Not found"})


def handle_login(event):
    """
    Authenticate username/password via the legacy API,
    then issue a short-lived JWT on success.
    """
    # Parse request body
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return response(400, {"error": "Invalid JSON body"})

    username = body.get("username", "").strip()
    password = body.get("password", "")

    if not username or not password:
        return response(400, {"error": "username and password are required"})

    # Call the legacy auth API (simulated)
    user_attrs = verify_with_legacy_api(username, password)

    if user_attrs is None:
        print(f"Login failed for user: {username}")
        return response(401, {"error": "Invalid username or password"})

    print(f"Login succeeded for user: {username}")

    # Issue JWT
    token = create_jwt(username, user_attrs)

    return response(200, {
        "token": token,
        "expires_in": TOKEN_EXPIRY_SECONDS,
        "token_type": "Bearer",
    })


# ---- JWT helpers (HS256, same pattern as Demo 2/3) ----

def create_jwt(username, user_attrs):
    """Create an HS256 JWT containing user identity and expiry."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "email": user_attrs.get("email", ""),
        "name": user_attrs.get("name", ""),
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS,
        "jti": str(uuid.uuid4()),  # unique token ID
    }

    header_b64 = base64url_encode(json.dumps(header))
    payload_b64 = base64url_encode(json.dumps(payload))
    signing_input = f"{header_b64}.{payload_b64}"

    signature = hmac.new(
        JWT_SECRET.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    signature_b64 = base64url_encode_bytes(signature)

    return f"{signing_input}.{signature_b64}"


def base64url_encode(data):
    """Base64url-encode a string."""
    return base64.urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("utf-8")


def base64url_encode_bytes(data):
    """Base64url-encode raw bytes."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def response(status_code, body):
    """Build API Gateway response with CORS headers."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
        },
        "body": json.dumps(body),
    }
