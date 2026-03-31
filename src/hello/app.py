"""
Simple Hello World Lambda — the protected backend behind the API Gateway.
If you reach this, it means the Duo authorizer approved your request.
"""

import json


def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({
            "message": "Hello from the protected API! Duo auth succeeded.",
        }),
    }
