"""
Simple Hello World Lambda — the protected backend behind the API Gateway.
If you reach this, it means the Duo authorizer approved your request.
"""

import json


def handler(event, context):
    # Extract claims passed from the Lambda authorizer
    authorizer_context = event.get("requestContext", {}).get("authorizer", {})

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({
            "message": "Hello from the protected API! Auth succeeded.",
            "claims": authorizer_context,
        }),
    }
