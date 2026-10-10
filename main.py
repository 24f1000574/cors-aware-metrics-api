import time
import uuid
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

ALLOWED_ORIGIN = "https://dash-kssbbx.example.com"
USER_EMAIL = "24f1000574@ds.study.iitm.ac.in"


class ProcessTimeAndRequestIdMiddleware:
    """
    ASGI middleware that ensures every HTTP response carries:
    - X-Request-ID: unique request identifier (UUID)
    - X-Process-Time: handler duration in seconds as a decimal number
    """
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                process_time = max(0.0, time.perf_counter() - start_time)
                headers.append((b"x-request-id", request_id.encode("latin1")))
                headers.append((b"x-process-time", f"{process_time:.6f}".encode("latin1")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


app = FastAPI(title="CORS-Aware Metrics API")

# 1. Enforce strict per-origin CORS policy (no wildcards)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
    max_age=600,
)

# 2. Add header middleware outside CORSMiddleware so all responses (including preflight) carry required headers
app.add_middleware(ProcessTimeAndRequestIdMiddleware)


@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "service": "CORS-Aware Metrics API",
        "email": USER_EMAIL,
    }


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
        # Fallback in case floats are passed
        try:
            nums = [float(v) for v in raw_items]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid numbers in values")

    count = len(nums)
    s = sum(nums)
    mn = min(nums)
    mx = max(nums)
    mean = float(s) / count

    # Return integer representations if inputs were integers
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
