# Lambda Authorizer with Cisco Duo — Demo Project

Four demos showing different ways to protect API Gateway REST APIs using Lambda Authorizers with Cisco Duo.

## Demos Overview

| Demo | Template | Auth Flow | Duo App Type |
|------|----------|-----------|--------------|
| 1 — Passcode MFA | `template-duo-passcode-mfa.yaml` | Client sends username:passcode, Lambda verifies via Duo Auth API | Auth API |
| 2 — OIDC 2FA | `template-duo-oidc-2fa.yaml` | App handles login, Duo handles 2FA via Universal Prompt, app issues JWT | Web SDK |
| 3 — SSO Full IdP | `template-duo-sso-full-idp.yaml` | Duo handles both password + 2FA, app issues JWT | Generic OIDC RP |
| 4 — SSO + PKCE | `template-duo-sso-pkce.yaml` | Frontend-only auth via PKCE, Duo's RS256 JWT used directly | Generic OIDC RP (PKCE) |

There is also a combined `template.yaml` that deploys all four demos at once.

## Project Structure

```
├── template.yaml                      # All demos combined
├── template-duo-passcode-mfa.yaml     # Demo 1 only
├── template-duo-oidc-2fa.yaml         # Demo 2 only
├── template-duo-sso-full-idp.yaml     # Demo 3 only
├── template-duo-sso-pkce.yaml         # Demo 4 only
├── samconfig.toml
├── src/
│   ├── authorizer/                    # Demo 1: Duo Auth API passcode authorizer
│   │   ├── app.py
│   │   └── requirements.txt
│   ├── duo_oidc/                      # Demo 2: Duo Universal Prompt login + callback
│   │   ├── app.py
│   │   └── requirements.txt
│   ├── duo_sso/                       # Demo 3: Duo SSO login + callback
│   │   └── app.py
│   ├── jwt_authorizer/                # Demo 2 & 3: HS256 JWT authorizer
│   │   └── app.py
│   ├── duo_jwt_authorizer/            # Demo 4: RS256 JWT authorizer (validates Duo tokens via JWKS)
│   │   └── app.py
│   └── hello/                         # Shared: protected backend Lambda
│       └── app.py
├── frontend/
│   ├── index-template.html            # Demo 2 frontend (template — copy to index.html)
│   ├── sso-template.html              # Demo 3 frontend (template — copy to sso.html)
│   └── sso-pkce-template.html         # Demo 4 frontend (template — copy to sso-pkce.html)
├── diagrams/
│   ├── demo1-passcode.drawio
│   ├── demo2-oidc.drawio
│   ├── demo3-sso.drawio
│   └── demo4-pkce.drawio
└── .kiro/
    └── steering/
        └── project-guidelines.md
```

## Prerequisites

- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- Python 3.12+
- Cisco Duo account (free trial: https://signup.duo.com)

## Duo Setup

Each demo requires a different Duo application. Create them in the Duo Admin Panel under Applications → Application Catalog:

| Demo | Duo Application | Key Values Needed |
|------|----------------|-------------------|
| 1 | Auth API (2FA label) | Integration Key, Secret Key, API Hostname |
| 2 | Web SDK (2FA label) | Client ID, Client Secret, API Hostname |
| 3 | Generic OIDC Relying Party (SSO label) | Client ID, Client Secret, Issuer URL |
| 4 | Same as Demo 3, with "Allow PKCE only authentication" enabled | Client ID, Issuer URL |

For all apps, set User access to "Allow access to all users".

For Demos 3 and 4, you also need Duo Directory set up as the authentication source with users that have passwords set.

## Deploy Individual Demos

```bash
# Pick a demo and deploy
sam build -t template-duo-passcode-mfa.yaml
sam deploy -t template-duo-passcode-mfa.yaml --stack-name duo-passcode-mfa --guided

sam build -t template-duo-oidc-2fa.yaml
sam deploy -t template-duo-oidc-2fa.yaml --stack-name duo-oidc-2fa --guided

sam build -t template-duo-sso-full-idp.yaml
sam deploy -t template-duo-sso-full-idp.yaml --stack-name duo-sso-full-idp --guided

sam build -t template-duo-sso-pkce.yaml
sam deploy -t template-duo-sso-pkce.yaml --stack-name duo-sso-pkce --guided
```

## Deploy All Demos at Once

```bash
sam build
sam deploy --guided
```

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

## Cleanup

```bash
# Delete individual stacks
sam delete --stack-name duo-passcode-mfa
sam delete --stack-name duo-oidc-2fa
sam delete --stack-name duo-sso-full-idp
sam delete --stack-name duo-sso-pkce

# Or delete the combined stack
sam delete --stack-name duo-lambda-authorizer-demo
```
