# OAuth 2.0 / OIDC Token Verification & Metrics API

A FastAPI service providing:
1. **OAuth 2.0 / OIDC Token Verification Service**: `POST /verify`
   - Validates RS256 JWT tokens against assigned IdP public key.
   - Enforces issuer (`https://idp.exam.local`), audience (`tds-e8pdjl8x.apps.exam.local`), and expiration time.
   - Responds 200 with `{"valid": true, ...claims}` on valid tokens.
   - Responds 401 with `{"valid": false}` on invalid, expired, wrong-audience, or tampered tokens.
2. **CORS-Aware Metrics API**: `GET /stats?values=...`
   - Computes count, sum, min, max, and mean.
   - Enforces strict per-origin CORS policy for `https://dash-kssbbx.example.com`.
3. **Middleware**:
   - Injects `X-Request-ID` (UUID) and `X-Process-Time` (seconds) into all responses.

## Local Development
```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```
