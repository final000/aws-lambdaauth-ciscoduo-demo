# Lambda Authorizer with Cisco Duo — Demo Project

Six demos showing different ways to protect API Gateway REST APIs using Lambda Authorizers, covering Cisco Duo integration and traditional auth patterns.

## Demos Overview

| Demo | Template | Auth Flow | Duo App Type |
|------|----------|-----------|--------------|
| 1 — Passcode MFA | `template-duo-passcode-mfa.yaml` | Client sends username:passcode, Lambda verifies via Duo Auth API | Auth API |
| 2 — OIDC 2FA | `template-duo-oidc-2fa.yaml` | App handles login, Duo handles 2FA via Universal Prompt, app issues JWT | Web SDK |
| 3 — SSO Full IdP | `template-duo-sso-full-idp.yaml` | Duo handles both password + 2FA, app issues JWT | Generic OIDC RP |
| 4 — SSO + PKCE | `template-duo-sso-pkce.yaml` | Frontend-only auth via PKCE, Duo's RS256 JWT used directly | Generic OIDC RP (PKCE) |
| 5 — Cognito Federation | `template-duo-cognito-federation.yaml` | Cognito federates to Duo SSO, Cognito issues tokens, no Lambda authorizer | Generic OIDC RP |
| 6 — Legacy Auth + JWT | `template-legacy-auth.yaml` | Classic username/password via legacy API, app issues JWT | None (no Duo) |

There is also a combined `template.yaml` that deploys all demos at once (Demo 5 is conditional on providing a Cognito domain prefix).

## Project Structure

```
├── template.yaml                        # All demos combined
├── template-duo-passcode-mfa.yaml       # Demo 1 only
├── template-duo-oidc-2fa.yaml           # Demo 2 only
├── template-duo-sso-full-idp.yaml       # Demo 3 only
├── template-duo-sso-pkce.yaml           # Demo 4 only
├── template-duo-cognito-federation.yaml # Demo 5 only
├── template-legacy-auth.yaml            # Demo 6 only
├── samconfig.toml
├── src/
│   ├── authorizer/                      # Demo 1: Duo Auth API passcode authorizer
│   │   ├── app.py
│   │   └── requirements.txt
│   ├── duo_oidc/                        # Demo 2: Duo Universal Prompt login + callback
│   │   ├── app.py
│   │   └── requirements.txt
│   ├── duo_sso/                         # Demo 3: Duo SSO login + callback
│   │   └── app.py
│   ├── jwt_authorizer/                  # Demo 2, 3 & 6: HS256 JWT authorizer
│   │   └── app.py
│   ├── duo_jwt_authorizer/              # Demo 4: RS256 JWT authorizer (validates Duo tokens via JWKS)
│   │   └── app.py
│   ├── legacy_login/                    # Demo 6: Username/password login, issues JWT
│   │   ├── app.py
│   │   └── requirements.txt
│   └── hello/                           # Shared: protected backend Lambda
│       └── app.py
├── frontend/
│   ├── index-template.html              # Demo 2 frontend (template — copy to index.html)
│   ├── sso-template.html                # Demo 3 frontend (template — copy to sso.html)
│   ├── sso-pkce-template.html           # Demo 4 frontend (template — copy to sso-pkce.html)
│   ├── cognito-callback-template.html   # Demo 5 frontend (template — copy to cognito-callback.html)
│   └── legacy-login-template.html       # Demo 6 frontend (template — copy to legacy-login.html)
├── diagrams/
│   ├── demo1-passcode.drawio
│   ├── demo2-oidc.drawio
│   ├── demo3-sso.drawio
│   ├── demo4-pkce.drawio
│   └── demo5-cognito.drawio
└── .kiro/
    └── steering/
        └── project-guidelines.md
```

## Prerequisites

- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- Python 3.12+
- Cisco Duo account with active trial or paid plan (Essentials or higher required for SSO in Demos 3–5). Demo 6 does not require Duo.

## Duo Setup

Each Duo demo requires a different Duo application. Create them in the Duo Admin Panel under Applications → Application Catalog:

| Demo | Duo Application | Key Values Needed |
|------|----------------|-------------------|
| 1 | Auth API (2FA label) | Integration Key, Secret Key, API Hostname |
| 2 | Web SDK (2FA label) | Client ID, Client Secret, API Hostname |
| 3 | Generic OIDC Relying Party (SSO label) | Client ID, Client Secret, Issuer URL |
| 4 | Same as Demo 3, with "Allow PKCE only authentication" enabled | Client ID, Issuer URL |
| 5 | Same as Demo 3 | Client ID, Client Secret, Issuer URL |
| 6 | *(none — no Duo required)* | — |

For all Duo apps, set User access to "Allow access to all users".

For Demos 3, 4, and 5, you also need Duo Directory set up as the authentication source with users that have passwords set.

## Deploy Individual Demos

```bash
# Demo 1: Passcode MFA
sam build -t template-duo-passcode-mfa.yaml
sam deploy -t template-duo-passcode-mfa.yaml --stack-name duo-passcode-mfa --guided

# Demo 2: OIDC 2FA
sam build -t template-duo-oidc-2fa.yaml
sam deploy -t template-duo-oidc-2fa.yaml --stack-name duo-oidc-2fa --guided

# Demo 3: SSO Full IdP
sam build -t template-duo-sso-full-idp.yaml
sam deploy -t template-duo-sso-full-idp.yaml --stack-name duo-sso-full-idp --guided

# Demo 4: SSO + PKCE
sam build -t template-duo-sso-pkce.yaml
sam deploy -t template-duo-sso-pkce.yaml --stack-name duo-sso-pkce --guided

# Demo 5: Cognito + Duo Federation
sam build -t template-duo-cognito-federation.yaml
sam deploy -t template-duo-cognito-federation.yaml --stack-name duo-cognito-federation --guided

# Demo 6: Legacy Username/Password Auth
sam build -t template-legacy-auth.yaml
sam deploy -t template-legacy-auth.yaml --stack-name legacy-auth --guided
```

## Deploy All Demos at Once

```bash
sam build
sam deploy --guided
```

Note: Demo 5 (Cognito federation) is only deployed if you provide a `CognitoDomainPrefix` parameter.

## Frontend Setup

The frontend HTML files with real configuration values are gitignored. Template files with placeholder values are provided instead.

After deploying, copy the template files and fill in your values:

```bash
cd frontend

# Demo 2
cp index-template.html index.html
# Edit index.html → replace API_BASE with your OidcApiBase stack output

# Demo 3
cp sso-template.html sso.html
# Edit sso.html → replace API_BASE with your SsoApiBase stack output

# Demo 4
cp sso-pkce-template.html sso-pkce.html
# Edit sso-pkce.html → replace DUO_SSO_CLIENT_ID, DUO_SSO_ISSUER, and API_BASE

# Demo 5
cp cognito-callback-template.html cognito-callback.html
# Edit cognito-callback.html → replace COGNITO_DOMAIN, CLIENT_ID, and API_BASE

# Demo 6
cp legacy-login-template.html legacy-login.html
# Edit legacy-login.html → replace API_BASE with your LegacyApiBase stack output
```

Then serve the frontend:

```bash
cd frontend
python3 -m http.server 8000
```

## Test

### Demo 1 — Passcode

```bash
curl -H "Authorization: Bearer test_user1:PASSCODE" "API_URL/hello"
```

### Demo 2 — OIDC 2FA

1. Copy `frontend/index-template.html` to `frontend/index.html` (see Frontend Setup above)
2. Update `API_BASE` with the `OidcApiBase` stack output
3. Run `cd frontend && python3 -m http.server 8000`
4. Open http://localhost:8000/index.html
5. Login with mock credentials, complete Duo 2FA, then call the protected API

### Demo 3 — SSO Full IdP

1. Add the `SsoCallbackUrl` stack output as a Sign-In Redirect URL in the Duo Admin Panel
2. Copy `frontend/sso-template.html` to `frontend/sso.html` (see Frontend Setup above)
3. Update `API_BASE` with the `SsoApiBase` stack output
4. Run `cd frontend && python3 -m http.server 8000`
5. Open http://localhost:8000/sso.html
6. Click login, enter Duo Directory email + password, complete 2FA, then call the protected API

### Demo 4 — SSO + PKCE

1. Enable "Allow PKCE only authentication" on the Duo Generic OIDC RP app
2. Add `http://localhost:8000/sso-pkce.html` as a Sign-In Redirect URL
3. Copy `frontend/sso-pkce-template.html` to `frontend/sso-pkce.html` (see Frontend Setup above)
4. Update `DUO_SSO_CLIENT_ID`, `DUO_SSO_ISSUER`, and `API_BASE`
5. Run `cd frontend && python3 -m http.server 8000`
6. Open http://localhost:8000/sso-pkce.html
7. Click login, complete Duo SSO login + 2FA, then call the protected API

### Demo 5 — Cognito + Duo Federation

1. Deploy the stack and note the `DuoCallbackUrl` output
2. In Duo Admin Panel → your OIDC RP app, add the `DuoCallbackUrl` as a Sign-In Redirect URL
3. Copy `frontend/cognito-callback-template.html` to `frontend/cognito-callback.html`
4. Update `COGNITO_DOMAIN`, `CLIENT_ID`, and `API_BASE` with stack outputs
5. Run `cd frontend && python3 -m http.server 8000`
6. Open http://localhost:8000/cognito-callback.html
7. Click login → Cognito Hosted UI → Duo SSO → 2FA → back to app with tokens

### Demo 6 — Legacy Username/Password Auth

1. Deploy the stack: `sam build -t template-legacy-auth.yaml && sam deploy -t template-legacy-auth.yaml --stack-name legacy-auth --guided`
2. Copy `frontend/legacy-login-template.html` to `frontend/legacy-login.html`
3. Update `API_BASE` with the `LegacyApiBase` stack output
4. Run `cd frontend && python3 -m http.server 8000`
5. Open http://localhost:8000/legacy-login.html
6. Login with: `demo_user` / `demo_pass` (or `test_user` / `test_pass`, `admin` / `admin123`)
7. Click "Call Protected API" to test JWT-authenticated access

You can also test with curl:

```bash
# Get a token
TOKEN=$(curl -s -X POST "API_URL/legacy/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"demo_user","password":"demo_pass"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Call protected endpoint
curl -H "Authorization: Bearer $TOKEN" "API_URL/legacy/protected"
```

## Cleanup

```bash
# Delete individual stacks
sam delete --stack-name duo-passcode-mfa
sam delete --stack-name duo-oidc-2fa
sam delete --stack-name duo-sso-full-idp
sam delete --stack-name duo-sso-pkce
sam delete --stack-name duo-cognito-federation
sam delete --stack-name legacy-auth

# Or delete the combined stack
sam delete --stack-name duo-lambda-authorizer-demo
```
