"""
Duo SSO (OIDC) Login Lambda — Demo 3.

Uses Duo Single Sign-On as a full identity provider (both password + 2FA).
This is a standard OAuth 2.0 Authorization Code flow where Duo handles
everything: the login page, password verification, and 2FA.

Flow:
1. POST /sso/login     — redirects browser to Duo SSO authorize endpoint
2. GET  /sso/callback   — Duo redirects here with auth code, we exchange
                           it for tokens and redirect to frontend

Duo SSO Generic OIDC docs: https://duo.com/docs/sso-oidc-generic
"""

import os
import json
import time
import uuid
import hmac
import hashlib
import base64
import secrets
import urllib.parse
import urllib.request


# ---- Config from environment variables ----
DUO_SSO_CLIENT_ID = os.environ.get("DUO_SSO_CLIENT_ID", "")
DUO_SSO_CLIENT_SECRET = os.environ.get("DUO_SSO_CLIENT_SECRET", "")
DUO_SSO_ISSUER = os.environ.get("DUO_SSO_ISSUER", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "")

# In-memory state store (demo only — use DynamoDB in production)
_state_store = {}


def handler(event, context):
    """Main Lambda handler — routes based on path."""
    path = event.get("path", "")
    method = event.get("httpMethod", "")

    if path == "/sso/login" and method == "POST":
        return handle_login(event)
    elif path == "/sso/callback" and method == "GET":
        return handle_callback(event)
    else:
        return response(404, {"error": "Not found"})


def get_callback_uri(event):
    """Build the callback URL from the incoming request context."""
    headers = event.get("headers", {})
    host = headers.get("Host", "")
    stage = event.get("requestContext", {}).get("stage", "Prod")
    return f"https://{host}/{stage}/sso/callback"


def handle_login(event):
    """
    Step 1: Redirect browser to Duo SSO authorize endpoint.
    No password needed here — Duo handles the entire login page.
    """
    redirect_uri = get_callback_uri(event)

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    _state_store[state] = {"timestamp": time.time()}

    # Build the Duo SSO authorization URL
    # This is a standard OIDC Authorization Code flow
    authorize_url = f"{DUO_SSO_ISSUER}/authorize"
    params = {
        "client_id": DUO_SSO_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
    }
    auth_url = f"{authorize_url}?{urllib.parse.urlencode(params)}"

    return response(200, {
        "duo_auth_url": auth_url,
        "message": "Redirect to Duo SSO for login + 2FA",
    })


def handle_callback(event):
    """
    Step 2: Duo SSO redirects here after successful login + 2FA.
    Exchange the auth code for tokens.
    """
    params = event.get("queryStringParameters") or {}
    code = params.get("code", "")
    state = params.get("state", "")

    if not code:
        return response(400, {"error": "Missing authorization code"})

    # Validate state
    stored = _state_store.pop(state, None)
    if not stored:
        return response(403, {"error": "Invalid or expired state"})

    redirect_uri = get_callback_uri(event)

    # Exchange auth code for tokens at Duo SSO token endpoint
    token_url = f"{DUO_SSO_ISSUER}/token"
    token_data = urllib.parse.urlencode({
        "client_id": DUO_SSO_CLIENT_ID,
        "client_secret": DUO_SSO_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }).encode("utf-8")

    req = urllib.request.Request(
        token_url,
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    try:
        with urllib.request.urlopen(req) as resp:
            token_response = json.loads(resp.read().decode("utf-8"))
        print(f"Duo SSO token response keys: {list(token_response.keys())}")
    except Exception as e:
        print(f"Token exchange failed: {e}")
        return response(500, {"error": "Token exchange failed"})

    # The id_token from Duo SSO is an RS256-signed JWT
    # For this demo, we issue our own simpler HS256 JWT
    # In production, you'd validate the Duo id_token using the JWKS endpoint
    id_token = token_response.get("id_token", "")
    if not id_token:
        return response(500, {"error": "No id_token in response"})

    # Decode the id_token payload (without verification — demo only)
    # In production, verify signature using Duo's JWKS endpoint
    payload = decode_jwt_payload(id_token)
    username = payload.get("email") or payload.get("sub", "unknown")
    print(f"Duo SSO authenticated user: {username}")

    # Issue our own JWT for the frontend
    jwt_token = create_jwt(username)

    # Redirect back to frontend with token
    redirect_url = f"{FRONTEND_URL}?token={jwt_token}&demo=sso"
    return {
        "statusCode": 302,
        "headers": {"Location": redirect_url},
        "body": "",
    }


# ---- JWT helpers ----

def decode_jwt_payload(token):
    """Decode JWT payload without verification (demo only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1]
        # Fix padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload
    except Exception as e:
        print(f"Failed to decode JWT: {e}")
        return {}


def create_jwt(username):
    """Create a simple HS256 JWT."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
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
