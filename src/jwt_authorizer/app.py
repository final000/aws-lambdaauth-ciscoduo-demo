"""
JWT Lambda Authorizer — validates JWT tokens issued after Duo OIDC 2FA.

This is a TOKEN-type authorizer for API Gateway REST API.
It verifies the HS256 JWT signature and checks expiry.

Note: This is a demo-grade JWT implementation. For production,
use a proper JWT library (PyJWT) and asymmetric keys (RS256).
"""

import os
import json
import time
import hmac
import hashlib
import base64


JWT_SECRET = os.environ.get("JWT_SECRET", "")


def handler(event, context):
    """API Gateway TOKEN authorizer handler."""
    token = event.get("authorizationToken", "")
    method_arn = event["methodArn"]

    # Expect: "Bearer <jwt>"
    if not token.startswith("Bearer "):
        print("Missing or malformed Bearer token")
        raise Exception("Unauthorized")

    jwt_token = token[len("Bearer "):]

    # Validate the JWT
    claims = verify_jwt(jwt_token)

    if claims:
        username = claims.get("sub", "unknown")
        print(f"JWT valid for user: {username}")
        policy = generate_policy(username, "Allow", method_arn)
        # Pass claims to backend Lambda via authorizer context
        # Note: context values must be strings, numbers, or booleans
        policy["context"] = {
            "sub": claims.get("sub", ""),
            "iat": claims.get("iat", 0),
            "exp": claims.get("exp", 0),
        }
        return policy
    else:
        print("JWT validation failed")
        return generate_policy("unknown", "Deny", method_arn)


def verify_jwt(token):
    """
    Verify an HS256 JWT token.
    Returns the payload claims if valid, None otherwise.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            print("JWT must have 3 parts")
            return None

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            JWT_SECRET.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        expected_sig_b64 = base64url_encode_bytes(expected_sig)

        if not hmac.compare_digest(signature_b64, expected_sig_b64):
            print("JWT signature mismatch")
            return None

        # Decode payload
        payload = json.loads(base64url_decode(payload_b64))

        # Check expiry
        exp = payload.get("exp", 0)
        if time.time() > exp:
            print("JWT expired")
            return None

        return payload

    except Exception as e:
        print(f"JWT verification error: {e}")
        return None


def base64url_decode(data):
    """Decode base64url-encoded string with padding fix."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data).decode("utf-8")


def base64url_encode_bytes(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def generate_policy(principal_id, effect, method_arn):
    """Build IAM policy for API Gateway."""
    arn_parts = method_arn.split(":")
    api_gateway_arn = ":".join(arn_parts[:5])
    rest_api_part = arn_parts[5].split("/")
    resource_arn = f"{api_gateway_arn}:{rest_api_part[0]}/{rest_api_part[1]}/*"

    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource_arn,
                }
            ],
        },
    }
