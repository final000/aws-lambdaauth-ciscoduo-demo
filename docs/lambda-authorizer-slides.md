# Lambda Authorizer with Cisco Duo — Slide Deck Content

---

## Slide 1: What is a Lambda Authorizer?

- A Lambda function that API Gateway calls BEFORE forwarding a request to the backend
- It decides: should this request be allowed or denied?
- Returns an IAM policy document to API Gateway
- API Gateway enforces the decision

```
Client → API Gateway → Lambda Authorizer → Allow/Deny → Backend Lambda
```

---

## Slide 2: How Lambda Authorizer Responds

Three possible outcomes:

| Outcome | How | Client sees |
|---------|-----|-------------|
| Allow | Return policy with `"Effect": "Allow"` | Request reaches backend, gets response |
| Deny | Return policy with `"Effect": "Deny"` | 403 Forbidden |
| Unauthorized | Raise `Exception("Unauthorized")` | 401 Unauthorized |

---

## Slide 3: Lambda Authorizer Response Format (REST API)

```json
{
    "principalId": "user@example.com",
    "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "execute-api:Invoke",
            "Effect": "Allow",
            "Resource": "arn:aws:execute-api:REGION:ACCOUNT:API_ID/STAGE/*"
        }]
    },
    "context": {
        "email": "user@example.com",
        "role": "admin"
    }
}
```

- `principalId`: who is this user
- `Effect`: Allow or Deny
- `Resource`: which API endpoints this policy covers (* = all)
- `context`: custom data forwarded to backend Lambda

---

## Slide 4: Two Types of Lambda Authorizer

| | TOKEN Authorizer | REQUEST Authorizer |
|---|---|---|
| Input | Single header value (e.g. Authorization) | Full request (headers, query params, path) |
| Use case | Bearer tokens, API keys | Multi-source auth (cookies + headers) |
| Our demos | All 4 demos use TOKEN type | Not used |

---

## Slide 5: Passing Claims to Backend Lambda

Lambda Authorizer → `context` field → API Gateway → `event.requestContext.authorizer`

```python
# In the authorizer
return {
    "principalId": "user1",
    "policyDocument": { ... },
    "context": { "email": "user@example.com", "role": "admin" }
}

# In the backend Lambda
def handler(event, context):
    email = event["requestContext"]["authorizer"]["email"]
    role = event["requestContext"]["authorizer"]["role"]
```

This is secure — the context is injected by API Gateway internally, not from the client.

---

## Slide 6: Lambda Authorizer vs Regular Lambda

| | Lambda Authorizer | Regular Lambda |
|---|---|---|
| Purpose | Authorization decision | Business logic |
| Returns | IAM policy document | HTTP response (statusCode, body) |
| Called by | API Gateway (before request) | API Gateway (after authorization) |
| Talks to client? | No (API Gateway interprets the policy) | Yes (response goes to client) |

---

## Slide 7: Four Demo Authentication Flows

| Demo | Auth Method | Who handles login? | Token type |
|------|-----------|-------------------|------------|
| 1 — Passcode | Duo Auth API | No login (API call) | No token (direct policy) |
| 2 — OIDC 2FA | Duo Web SDK | Your app (password) + Duo (2FA) | Custom HS256 JWT |
| 3 — SSO Full IdP | Duo SSO | Duo (password + 2FA) | Custom HS256 JWT |
| 4 — SSO + PKCE | Duo SSO + PKCE | Duo (password + 2FA) | Duo's RS256 JWT |

---

## Slide 8: JWT Signing — HS256 vs RS256

| | HS256 (Demos 2 & 3) | RS256 (Demo 4) |
|---|---|---|
| Type | Symmetric (shared secret) | Asymmetric (key pair) |
| Sign with | Shared secret | Private key (Duo holds it) |
| Verify with | Same shared secret | Public key (from JWKS endpoint) |
| Who can create tokens? | Anyone with the secret | Only the private key holder |
| Key management | You manage the secret | Duo manages keys, you fetch public keys |

---

## Slide 9: What is PKCE?

**P**roof **K**ey for **C**ode **E**xchange (RFC 7636)

1. Browser generates random `code_verifier`
2. Browser hashes it → `code_challenge` (SHA-256)
3. Sends `code_challenge` to IdP with auth request
4. User logs in, IdP redirects back with auth code
5. Browser sends auth code + `code_verifier` to token endpoint
6. IdP hashes `code_verifier`, compares with stored `code_challenge`
7. Match → issue tokens

**Security**: stolen auth code is useless without the `code_verifier`

---

## Slide 10: Security Comparison

| Aspect | Demo 1 | Demo 2 | Demo 3 | Demo 4 |
|--------|--------|--------|--------|--------|
| Password managed by | Your app | Your app | Duo | Duo |
| 2FA managed by | Duo | Duo | Duo | Duo |
| Secrets in backend | Duo IKEY/SKEY | Duo Client Secret + JWT Secret | Duo Client Secret + JWT Secret | None |
| Token in browser | No | Yes (JWT) | Yes (JWT) | Yes (JWT) |
| Can forge tokens? | N/A | Only with JWT Secret | Only with JWT Secret | Only with Duo's private key |

---

## Slide 11: When to Use Which Demo

- **Demo 1**: APIs, CLIs, server-to-server — no browser needed
- **Demo 2**: Web apps with existing user database — add 2FA on top
- **Demo 3**: Web apps wanting Duo as full IdP — no user database needed
- **Demo 4**: SPAs/frontends wanting simplest setup — no backend auth Lambda needed

---

## Slide 12: Architecture Diagrams

See `diagrams/` folder for draw.io files:
- `demo1-passcode.drawio`
- `demo2-oidc.drawio`
- `demo3-sso.drawio`
- `demo4-pkce.drawio`
