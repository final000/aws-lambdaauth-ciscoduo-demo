"""
Lambda Authorizer — validates requests using Cisco Duo Auth API.

Flow:
1. Client sends request with Authorization header containing "Bearer <username>:<passcode>"
2. This authorizer extracts username and passcode
3. Calls Duo Auth API /auth/v2/auth to verify the passcode
4. Returns an IAM policy allowing or denying access

Duo Auth API docs: https://duo.com/docs/authapi
"""

import os
import duo_client


def handler(event, context):
    """API Gateway TOKEN authorizer handler."""
    token = event.get("authorizationToken", "")
    method_arn = event["methodArn"]

    # Expect header format: "Bearer <username>:<passcode>"
    if not token.startswith("Bearer "):
        print("Missing or malformed Bearer token")
        raise Exception("Unauthorized")  # Return 401

    credentials = token[len("Bearer "):]
    parts = credentials.split(":", 1)
    if len(parts) != 2:
        print("Token must be in format username:passcode")
        raise Exception("Unauthorized")

    username, passcode = parts

    # Authenticate with Duo Auth API
    allowed = verify_duo(username, passcode)

    effect = "Allow" if allowed else "Deny"
    print(f"Authorizer decision: {effect} for user '{username}'")
    policy = generate_policy(username, effect, method_arn)
    print(f"Returning policy: {policy}")
    return policy


def verify_duo(username, passcode):
    """
    Call Duo Auth API to verify a passcode for the given user.
    Uses the duo_client library which handles HMAC signing automatically.

    Returns True if authentication succeeded, False otherwise.
    """
    ikey = os.environ["DUO_IKEY"]
    skey = os.environ["DUO_SKEY"]
    host = os.environ["DUO_HOST"]

    auth_api = duo_client.Auth(ikey=ikey, skey=skey, host=host)

    try:
        # First call /preauth to check user status and available devices
        preauth_response = auth_api.preauth(username=username)
        print(f"Duo preauth for user '{username}': {preauth_response}")

        # Call /auth/v2/auth with passcode factor
        # See: https://duo.com/docs/authapi#/auth
        response = auth_api.auth(
            factor="passcode",
            username=username,
            passcode=passcode,
        )
        print(f"Duo auth response for user '{username}': {response}")

        # Duo returns {"result": "allow", ...} on success
        return response.get("result") == "allow"

    except Exception as e:
        print(f"Duo Auth API error: {e}")
        return False


def generate_policy(principal_id, effect, method_arn):
    """
    Build the IAM policy document that API Gateway expects
    from a TOKEN authorizer.
    """
    # Use wildcard ARN so the policy covers all methods on this API
    # (avoids issues with cached authorizer responses)
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
