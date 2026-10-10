import time
import uuid
from typing import Optional
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
import jwt

USER_EMAIL = "24f1000574@ds.study.iitm.ac.in"
ALLOWED_ORIGIN_STATS = "https://dash-kssbbx.example.com"

IDP_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-e8pdjl8x.apps.exam.local"


class GlobalMiddleware:
    """
    ASGI middleware that ensures every HTTP response carries:
    - X-Request-ID: unique request identifier (UUID)
    - X-Process-Time: handler duration in seconds as a non-negative decimal number
    - CORS headers: strict per-origin on /stats, permissive on /verify and others
    """
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())
        path = scope.get("path", "")
        method = scope.get("method", "")

        # Extract origin header
        headers = dict(scope.get("headers", []))
        origin_bytes = headers.get(b"origin")
        origin_str = origin_bytes.decode("latin1") if origin_bytes else None

        # Preflight OPTIONS handling
        if method == "OPTIONS":
            process_time = max(0.0, time.perf_counter() - start_time)
            resp_headers = [
                (b"x-request-id", request_id.encode("latin1")),
                (b"x-process-time", f"{process_time:.6f}".encode("latin1")),
            ]

            if path == "/stats":
                if origin_str == ALLOWED_ORIGIN_STATS:
                    resp_headers.extend([
                        (b"access-control-allow-origin", ALLOWED_ORIGIN_STATS.encode("latin1")),
                        (b"access-control-allow-credentials", b"true"),
                        (b"access-control-allow-methods", b"GET, POST, OPTIONS, HEAD"),
                        (b"access-control-allow-headers", b"*"),
                        (b"access-control-max-age", b"600"),
                        (b"vary", b"Origin"),
                    ])
                    status = 200
                else:
                    # Evil / unallowed origin preflight rejected with no ACAO header
                    status = 400
            else:
                # Other routes: allow preflight
                allowed_hdr = origin_bytes if origin_bytes else b"*"
                resp_headers.extend([
                    (b"access-control-allow-origin", allowed_hdr),
                    (b"access-control-allow-credentials", b"true"),
                    (b"access-control-allow-methods", b"GET, POST, OPTIONS, HEAD, PUT, DELETE, PATCH"),
                    (b"access-control-allow-headers", b"*"),
                    (b"access-control-max-age", b"600"),
                ])
                if origin_bytes:
                    resp_headers.append((b"vary", b"Origin"))
                status = 200

            await send({
                "type": "http.response.start",
                "status": status,
                "headers": resp_headers,
            })
            await send({
                "type": "http.response.body",
                "body": b"",
            })
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                resp_headers = list(message.get("headers", []))
                process_time = max(0.0, time.perf_counter() - start_time)
                resp_headers.append((b"x-request-id", request_id.encode("latin1")))
                resp_headers.append((b"x-process-time", f"{process_time:.6f}".encode("latin1")))

                if path == "/stats":
                    if origin_str == ALLOWED_ORIGIN_STATS:
                        resp_headers.append((b"access-control-allow-origin", ALLOWED_ORIGIN_STATS.encode("latin1")))
                        resp_headers.append((b"access-control-allow-credentials", b"true"))
                        resp_headers.append((b"vary", b"Origin"))
                else:
                    if origin_bytes:
                        resp_headers.append((b"access-control-allow-origin", origin_bytes))
                        resp_headers.append((b"access-control-allow-credentials", b"true"))
                        resp_headers.append((b"vary", b"Origin"))
                    else:
                        resp_headers.append((b"access-control-allow-origin", b"*"))

                message["headers"] = resp_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


app = FastAPI(title="Token Verification & Metrics API")
app.add_middleware(GlobalMiddleware)


@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "service": "Token Verification & Metrics API",
        "email": USER_EMAIL,
    }


# ==========================================
# POST /verify Endpoint (Question 4)
# ==========================================
@app.post("/verify")
async def verify_token(request: Request):
    token = None
    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            body = await request.json()
            if isinstance(body, dict):
                token = body.get("token")
        else:
            try:
                body = await request.json()
                if isinstance(body, dict):
                    token = body.get("token")
            except Exception:
                pass

            if not token:
                try:
                    form = await request.form()
                    token = form.get("token")
                except Exception:
                    pass
    except Exception:
        pass

    if not token:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
        elif "token" in request.query_params:
            token = request.query_params["token"]

    if not token or not isinstance(token, str):
        return JSONResponse(status_code=401, content={"valid": False})

    token = token.strip()

    try:
        payload = jwt.decode(
            token,
            IDP_PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "verify_signature": True,
                "require": ["exp", "iss", "aud"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except Exception:
        return JSONResponse(status_code=401, content={"valid": False})

    response_data = {"valid": True}
    response_data.update(payload)
    response_data["valid"] = True
    return JSONResponse(status_code=200, content=response_data)


# ==========================================
# GET /stats Endpoint (Question 3)
# ==========================================
@app.get("/stats")
def get_stats(values: str = Query(..., description="Comma-separated integers")):
    if not values:
        raise HTTPException(status_code=400, detail="values query parameter cannot be empty")

    raw_items = [v.strip() for v in values.split(",") if v.strip()]
    if not raw_items:
        raise HTTPException(status_code=400, detail="No valid numbers provided in values")

    try:
        nums = [int(v) for v in raw_items]
    except ValueError:
        try:
            nums = [float(v) for v in raw_items]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid numbers in values")

    count = len(nums)
    s = sum(nums)
    mn = min(nums)
    mx = max(nums)
    mean = float(s) / count

    return {
        "email": USER_EMAIL,
        "count": count,
        "sum": int(s) if isinstance(s, int) or (isinstance(s, float) and s.is_integer() and all(isinstance(x, int) for x in nums)) else s,
        "min": int(mn) if isinstance(mn, int) else mn,
        "max": int(mx) if isinstance(mx, int) else mx,
        "mean": round(mean, 6),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
