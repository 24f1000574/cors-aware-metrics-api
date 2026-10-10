# CORS-Aware Metrics API

A FastAPI service that computes descriptive statistics and enforces a strict per-origin CORS policy.

## Features
- **Strict CORS policy**: Exclusively allows `https://dash-kssbbx.example.com` (no wildcards).
- **Mandatory Custom Middleware**: Injects `X-Request-ID` (UUID) and `X-Process-Time` (seconds) into all responses (including preflight responses).
- **Descriptive Statistics Endpoint**: `GET /stats?values=...` calculates count, sum, min, max, and mean.

## Local Development
```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```
