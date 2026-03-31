"""
RS256 JWT Lambda Authorizer — validates Duo SSO access tokens directly.

Instead of minting our own JWTs, this authorizer validates the RS256 JWT
issued by Duo SSO using Duo's public keys from their JWKS endpoint.

This is the production-recommended approach: trust the IdP's tokens directly.

Duo SSO OIDC docs: https://duo.com/docs/sso-oidc-generic
"""

import os
import json
import time
import hmac
import hashlib
import base64
import struct
import urllib.request


DUO_SSO_ISSUER = os.environ.get("DUO_SSO_ISSUER", "")
DUO_SSO_CLIENT_ID = os.environ.get("DUO_SSO_CLIENT_ID", "")

# Cache JWKS keys in memory (Lambda container reuse)
_jwks_cache = {"keys": None, "fetched_at": 0}
JWKS_CACHE_TTL = 3600  # 1 hour


def handler(event, context):
    """API Gateway TOKEN authorizer handler."""
    token = event.get("authorizationToken", "")
    method_arn = event["methodArn"]

    if not token.startswith("Bearer "):
        print("Missing or malformed Bearer token")
        raise Exception("Unauthorized")

    jwt_token = token[len("Bearer "):]

    claims = verify_duo_jwt(jwt_token)
    if claims:
        principal = claims.get("sub", "unknown")
        print(f"Duo JWT valid for: {principal}")
        return generate_policy(principal, "Allow", method_arn)
    else:
        print("Duo JWT validation failed")
        return generate_policy("unknown", "Deny", method_arn)


def verify_duo_jwt(token):
    """
    Verify a Duo SSO RS256 JWT.
    1. Decode header to get kid (key ID)
    2. Fetch Duo's JWKS to get the matching public key
    3. Verify signature, issuer, audience, and expiry
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            print("JWT must have 3 parts")
            return None

        header_b64, payload_b64, signature_b64 = parts

        # Decode header to get kid and alg
        header = json.loads(b64url_decode(header_b64))
        if header.get("alg") != "RS256":
            print(f"Unsupported algorithm: {header.get('alg')}")
            return None

        kid = header.get("kid")
        if not kid:
            print("No kid in JWT header")
            return None

        # Get the public key from Duo's JWKS
        public_key = get_jwk_by_kid(kid)
        if not public_key:
            print(f"No matching key found for kid: {kid}")
            return None

        # Verify RS256 signature
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = b64url_decode_bytes(signature_b64)

        if not verify_rs256(signing_input, signature, public_key):
            print("RS256 signature verification failed")
            return None

        # Decode and validate payload
        payload = json.loads(b64url_decode(payload_b64))

        # Check issuer
        if payload.get("iss") != DUO_SSO_ISSUER:
            print(f"Issuer mismatch: {payload.get('iss')} != {DUO_SSO_ISSUER}")
            return None

        # Check audience
        if payload.get("aud") != DUO_SSO_CLIENT_ID:
            print(f"Audience mismatch: {payload.get('aud')} != {DUO_SSO_CLIENT_ID}")
            return None

        # Check expiry
        if time.time() > payload.get("exp", 0):
            print("JWT expired")
            return None

        return payload

    except Exception as e:
        print(f"JWT verification error: {e}")
        return None


def get_jwk_by_kid(kid):
    """Fetch Duo's JWKS and find the key matching the kid."""
    now = time.time()

    # Use cached keys if fresh
    if _jwks_cache["keys"] and (now - _jwks_cache["fetched_at"]) < JWKS_CACHE_TTL:
        for key in _jwks_cache["keys"]:
            if key.get("kid") == kid:
                return key
        return None

    # Fetch JWKS from Duo
    jwks_url = f"{DUO_SSO_ISSUER}/jwks"
    print(f"Fetching JWKS from: {jwks_url}")

    try:
        req = urllib.request.Request(jwks_url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            jwks = json.loads(resp.read().decode("utf-8"))

        _jwks_cache["keys"] = jwks.get("keys", [])
        _jwks_cache["fetched_at"] = now

        for key in _jwks_cache["keys"]:
            if key.get("kid") == kid:
                return key
        return None

    except Exception as e:
        print(f"Failed to fetch JWKS: {e}")
        return None


def verify_rs256(message, signature, jwk):
    """
    Verify RS256 signature using the JWK public key.
    Pure Python implementation — no external crypto libraries needed.
    """
    # Extract n and e from JWK
    n = int.from_bytes(b64url_decode_bytes(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode_bytes(jwk["e"]), "big")

    # RSA verify: signature^e mod n
    sig_int = int.from_bytes(signature, "big")
    decrypted = pow(sig_int, e, n)

    # Convert back to bytes (key size)
    key_size = (n.bit_length() + 7) // 8
    decrypted_bytes = decrypted.to_bytes(key_size, "big")

    # PKCS#1 v1.5 padding: 0x00 0x01 [padding 0xFF...] 0x00 [DigestInfo + hash]
    # SHA-256 DigestInfo prefix
    sha256_prefix = bytes([
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    ])

    # Compute expected hash
    expected_hash = hashlib.sha256(message).digest()
    expected_suffix = sha256_prefix + expected_hash

    # Verify padding structure
    if decrypted_bytes[0] != 0x00 or decrypted_bytes[1] != 0x01:
        return False

    # Find the 0x00 separator after padding
    separator_idx = decrypted_bytes.index(0x00, 2)
    # All bytes between index 2 and separator should be 0xFF
    padding = decrypted_bytes[2:separator_idx]
    if not all(b == 0xFF for b in padding):
        return False

    actual_suffix = decrypted_bytes[separator_idx + 1:]
    return actual_suffix == expected_suffix


# ---- Base64url helpers ----

def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data).decode("utf-8")


def b64url_decode_bytes(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.urlsafe_b64decode(data)


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
