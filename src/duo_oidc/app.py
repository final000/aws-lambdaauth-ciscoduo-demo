"""
Duo Universal Prompt (OIDC) Login Lambda.

Handles the full login flow:
1. POST /login       — mock primary auth, then redirect to Duo for 2FA
2. GET  /duo-callback — Duo redirects here after 2FA, we exchange the code
                         and issue a JWT for the frontend

Duo Web SDK v4 docs: https://duo.com/docs/duoweb
"""

import os
import json
import time
import uuid
import hmac
import hashlib
import base64
import duo_universal


# ---- Config from environment variables ----
DUO_CLIENT_ID = os.environ.get("DUO_CLIENT_ID", "")
DUO_CLIENT_SECRET = os.environ.get("DUO_CLIENT_SECRET", "")
DUO_API_HOST = os.environ.get("DUO_API_HOST", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "")

# Mock user database — keep it simple for the demo
# IMPORTANT: the username here must match a user in your Duo account
MOCK_USERS = {
    "demo_user": "demo_pass",
    "test_user1": "demo_pass",
}

# In-memory state store (for demo only — not suitable for production)
# In a real app, use DynamoDB or another persistent store
_state_store = {}


def handler(event, context):
    """Main Lambda handler — routes based on path and method."""
    path = event.get("path", "")
    method = event.get("httpMethod", "")

    if path == "/oidc/login" and method == "POST":
        return handle_login(event)
    elif path == "/oidc/duo-callback" and method == "GET":
        return handle_duo_callback(event)
    else:
        return response(404, {"error": "Not found"})


def get_redirect_uri(event):
    """Build the Duo callback URL from the incoming request context."""
    headers = event.get("headers", {})
    # API Gateway provides the host and stage in the request
    host = headers.get("Host", "")
    stage = event.get("requestContext", {}).get("stage", "Prod")
    return f"https://{host}/{stage}/oidc/duo-callback"


def handle_login(event):
    """
    Step 1: Mock primary authentication, then redirect to Duo Universal Prompt.
    Expects JSON body: {"username": "...", "password": "..."}
    """
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return response(400, {"error": "Invalid JSON body"})

    username = body.get("username", "")
    password = body.get("password", "")

    # Mock primary auth check
    if MOCK_USERS.get(username) != password:
        return response(401, {"error": "Invalid username or password"})

    # Build redirect URI dynamically from the request
    redirect_uri = get_redirect_uri(event)
    print(f"Duo redirect URI: {redirect_uri}")

    # Initialize Duo Universal client
    duo_client = duo_universal.Client(
        client_id=DUO_CLIENT_ID,
        client_secret=DUO_CLIENT_SECRET,
        host=DUO_API_HOST,
        redirect_uri=redirect_uri,
    )

    # Health check — make sure Duo is reachable
    try:
        duo_client.health_check()
    except Exception as e:
        print(f"Duo health check failed: {e}")
        return response(503, {"error": "Duo service unavailable"})

    # Generate state for CSRF protection
    state = duo_client.generate_state()

    # Store state → username mapping (demo: in-memory, production: use DynamoDB)
    _state_store[state] = {
        "username": username,
        "timestamp": time.time(),
    }

    # Create the Duo auth URL and redirect the user
    auth_url = duo_client.create_auth_url(username, state)

    return response(200, {
        "duo_auth_url": auth_url,
        "message": "Redirect to Duo for 2FA",
    })


def handle_duo_callback(event):
    """
    Step 2: Duo redirects here after 2FA.
    Query params: state, duo_code
    On success, issues a JWT and redirects to the frontend.
    """
    params = event.get("queryStringParameters") or {}
    state = params.get("state", "")
    duo_code = params.get("duo_code", "")

    if not state or not duo_code:
        return response(400, {"error": "Missing state or duo_code"})

    # Validate state
    stored = _state_store.pop(state, None)
    if not stored:
        return response(403, {"error": "Invalid or expired state"})

    username = stored["username"]

    # Initialize Duo client and exchange the code
    redirect_uri = get_redirect_uri(event)
    duo_client = duo_universal.Client(
        client_id=DUO_CLIENT_ID,
        client_secret=DUO_CLIENT_SECRET,
        host=DUO_API_HOST,
        redirect_uri=redirect_uri,
    )

    try:
        decoded_token = duo_client.exchange_authorization_code_for_2fa_result(
            duo_code, username
        )
        print(f"Duo 2FA success for '{username}': {decoded_token}")
    except Exception as e:
        print(f"Duo 2FA failed for '{username}': {e}")
        return response(403, {"error": "Duo authentication failed"})

    # Issue our own JWT for the frontend to use with the protected API
    jwt_token = create_jwt(username)

    # Redirect back to frontend with the token
    redirect_url = f"{FRONTEND_URL}?token={jwt_token}"

    return {
        "statusCode": 302,
        "headers": {"Location": redirect_url},
        "body": "",
    }


# ---- JWT helpers (minimal, demo-only implementation) ----

def create_jwt(username):
    """Create a simple HS256 JWT with username and expiry."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour expiry
        "jti": str(uuid.uuid4()),
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
    return base64.urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("utf-8")


def base64url_encode_bytes(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }
