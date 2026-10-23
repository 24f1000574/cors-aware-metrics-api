import os
import re
import sys
import json
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from storage import (
    init_db,
    canonical_hash,
    get_idempotency_record,
    save_idempotency_record,
    get_task,
    list_tasks,
    save_task
)
from ai_reasoning import process_invoice_batch

app = FastAPI(title="A2A Invoice Agent")

# Normalize duplicate consecutive slashes so both /a2a/path and /a2a//path work
@app.middleware("http")
async def normalize_path_middleware(request: Request, call_next):
    path = request.scope.get("path", "")
    normalized_path = re.sub(r'/+', '/', path)
    if normalized_path != path:
        request.scope["path"] = normalized_path
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@app.on_event("startup")
def on_startup():
    init_db()

def a2a_response(content: Any, status_code: int = 200) -> Response:
    body = json.dumps(content, separators=(',', ':'))
    return Response(
        content=body,
        status_code=status_code,
        media_type="application/a2a+json",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "Authorization, A2A-Version, Content-Type, Accept",
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return a2a_response({"error": exc.detail}, status_code=exc.status_code)

@app.options("/{full_path:path}")
async def options_preflight(full_path: str):
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "Authorization, A2A-Version, Content-Type, Accept",
        }
    )

# In-memory locks per task ID for atomic concurrency (e.g. cancel vs continuation race)
TASK_LOCKS: Dict[str, asyncio.Lock] = {}
LOCKS_MUTEX = asyncio.Lock()

async def get_task_lock(task_id: str) -> asyncio.Lock:
    async with LOCKS_MUTEX:
        if task_id not in TASK_LOCKS:
            TASK_LOCKS[task_id] = asyncio.Lock()
        return TASK_LOCKS[task_id]

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def get_base_url(request: Request) -> str:
    env_base = os.getenv("BASE_URL")
    if env_base:
        return env_base.rstrip("/")
    host = request.headers.get("host", "localhost:8000")
    scheme = "https" if "trycloudflare.com" in host or "onrender.com" in host or "vercel.app" in host else request.url.scheme
    return f"{scheme}://{host}/a2a"

def build_agent_card(base_url: str) -> Dict[str, Any]:
    clean_base = base_url.rstrip("/")
    return {
        "name": "Invoice Action Agent",
        "description": "Safe A2A 1.0 autonomous agent for invoice package verification, action proposals, and receipt settlement.",
        "version": "1.0.0",
        "capabilities": {
            "pushNotifications": False,
            "streaming": False
        },
        "skills": [
            {
                "id": "invoice_action_agent",
                "name": "Invoice Action Agent",
                "description": "Evaluates commercial invoice packages against policy, proposes evidence-backed actions, and records approved executions.",
                "tags": ["finance", "invoice", "settlement", "compliance"]
            }
        ],
        "defaultInputModes": [
            "application/vnd.ga5.invoice-claim-batch+json"
        ],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ],
        "supportedInterfaces": [
            {
                "url": clean_base,
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            },
            {
                "url": f"{clean_base}/",
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            }
        ]
    }

def authenticate_and_validate(request: Request) -> str:
    """
    CRITICAL: Validates Authorization FIRST (returning 401 on missing auth),
    and validates A2A-Version: 1.0 SECOND (returning 400 on invalid version).
    """
    # 1. Check Authentication FIRST
    auth_hdr = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_hdr or not auth_hdr.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header. Expected Bearer token."
        )

    token = auth_hdr[len("Bearer "):].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Empty Bearer token."
        )

    # 2. Check A2A-Version SECOND
    version_hdr = request.headers.get("a2a-version") or request.headers.get("A2A-Version")
    if not version_hdr or version_hdr.strip() != "1.0":
        raise HTTPException(
            status_code=400,
            detail="Unsupported or missing A2A-Version. Expected 1.0."
        )

    # 3. Check Content-Type for POST requests: require application/a2a+json
    if request.method == "POST":
        ct = request.headers.get("content-type") or request.headers.get("Content-Type") or ""
        media_type = ct.split(";")[0].strip().lower()
        if media_type != "application/a2a+json":
            raise HTTPException(
                status_code=415,
                detail="Unsupported Media Type. Expected Content-Type: application/a2a+json"
            )

    return token

# ----------------- Discovery & Root Routes -----------------

@app.get("/")
@app.get("/a2a")
@app.get("/a2a/")
@app.head("/")
@app.head("/a2a")
@app.head("/a2a/")
async def root_discovery(request: Request):
    base_url = get_base_url(request)
    card = build_agent_card(base_url)
    return a2a_response(card)

@app.get("/internal/diagnostics")
@app.get("/a2a/internal/diagnostics")
async def get_diagnostics():
    from storage import get_db
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT action, COUNT(*) FROM decision_cache GROUP BY action")
    action_counts = dict(c.fetchall())
    c.execute("SELECT task_id, proposals_json, task_json FROM tasks ORDER BY rowid DESC LIMIT 3")
    sample_tasks = []
    for row in c.fetchall():
        sample_tasks.append({
            "task_id": row["task_id"],
            "proposals": json.loads(row["proposals_json"]) if row["proposals_json"] else [],
            "task": json.loads(row["task_json"]) if row["task_json"] else {}
        })
    conn.close()
    return a2a_response({
        "action_counts": action_counts,
        "sample_tasks": sample_tasks
    })

@app.get("/.well-known/agent-card.json")
@app.get("/a2a/.well-known/agent-card.json")
async def get_agent_card(request: Request):
    base_url = get_base_url(request)
    card = build_agent_card(base_url)
    return a2a_response(card)

# ----------------- Message Send Route -----------------

@app.post("/message:send")
@app.post("/a2a/message:send")
async def send_message(request: Request):
    principal = authenticate_and_validate(request)
    
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    message = body.get("message")
    if not isinstance(message, dict):
        raise HTTPException(status_code=400, detail="Missing or invalid 'message' field.")

    message_id = message.get("messageId")
    if not message_id:
        raise HTTPException(status_code=400, detail="Missing 'messageId' in message.")

    # Idempotency hash computed on message only (ignore configuration)
    msg_hash = canonical_hash(message)

    # Check idempotency record
    idem_rec = get_idempotency_record(principal, message_id)
    if idem_rec:
        if idem_rec["message_hash"] != msg_hash:
            return a2a_response({
                "error": "IDEMPOTENCY_CONFLICT",
                "message": "Message ID reused with changed semantic content."
            }, status_code=409)
        task = get_task(idem_rec["task_id"], principal)
        if task:
            return a2a_response({"task": task})

    # Determine message type from parts
    parts = message.get("parts", [])
    if not parts or not isinstance(parts, list):
        raise HTTPException(status_code=400, detail="Message has no parts.")

    first_part = parts[0]
    media_type = first_part.get("mediaType", "")
    part_data = first_part.get("data", {})

    # 1. Initial Batch Submission
    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        batch_id = part_data.get("batchId", str(uuid.uuid4()))
        packages = part_data.get("packages", [])

        # Process packages through AI reasoning & caching
        proposals = process_invoice_batch(packages)

        task_id = f"task_{uuid.uuid4().hex[:16]}"
        context_id = f"ctx_{uuid.uuid4().hex[:16]}"
        now_iso = now_iso_utc()

        proposal_artifact = {
            "artifactId": f"proposals-{batch_id}",
            "name": "invoice-action-proposals",
            "parts": [
                {
                    "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                    "data": {
                        "batchId": batch_id,
                        "proposals": proposals
                    }
                }
            ]
        }

        task = {
            "id": task_id,
            "contextId": context_id,
            "state": "TASK_STATE_INPUT_REQUIRED",
            "status": {
                "state": "TASK_STATE_INPUT_REQUIRED",
                "timestamp": now_iso
            },
            "artifacts": [proposal_artifact],
            "history": [message],
            "createdAt": now_iso,
            "updatedAt": now_iso
        }

        save_task(task, principal, batch_id, proposals)
        save_idempotency_record(principal, message_id, msg_hash, task_id, {"task": task})

        return a2a_response({"task": task})

    # 2. Result Continuation Submission
    elif media_type == "application/vnd.ga5.invoice-action-results+json":
        task_id = message.get("taskId")
        context_id = message.get("contextId")
        if not task_id:
            raise HTTPException(status_code=400, detail="Continuation missing taskId.")

        task_lock = await get_task_lock(task_id)
        async with task_lock:
            task = get_task(task_id, principal)
            if not task:
                raise HTTPException(status_code=404, detail="Task not found.")

            curr_state = task.get("status", {}).get("state")
            if curr_state == "TASK_STATE_CANCELED":
                return a2a_response({
                    "error": "TASK_TERMINAL_CONFLICT",
                    "message": "Task was already canceled."
                }, status_code=409)
            if curr_state == "TASK_STATE_COMPLETED":
                return a2a_response({
                    "error": "TASK_TERMINAL_CONFLICT",
                    "message": "Task is already completed."
                }, status_code=409)

            # Validate contextId
            if context_id and context_id != task.get("contextId"):
                raise HTTPException(status_code=400, detail="contextId mismatch.")

            # Load stored proposals from database
            from storage import get_db
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT proposals_json, batch_id FROM tasks WHERE task_id = ?", (task_id,))
            row = cursor.fetchone()
            conn.close()

            stored_proposals = json.loads(row["proposals_json"]) if row else []
            stored_batch_id = row["batch_id"] if row else ""
            proposal_map = {p["packageId"]: p for p in stored_proposals}

            # Validate batchId
            if part_data.get("batchId") != stored_batch_id:
                raise HTTPException(status_code=400, detail="batchId mismatch.")

            results = part_data.get("results", [])
            executions = []

            for res in results:
                pkg_id = res.get("packageId")
                if pkg_id not in proposal_map:
                    raise HTTPException(status_code=400, detail=f"Unknown packageId {pkg_id}.")

                prop = proposal_map[pkg_id]
                # Validate actionId and action match stored proposal
                if res.get("actionId") != prop["actionId"]:
                    raise HTTPException(status_code=400, detail=f"actionId mismatch for package {pkg_id}.")
                if res.get("action") != prop["action"]:
                    raise HTTPException(status_code=400, detail=f"action mismatch for package {pkg_id}.")

                if res.get("outcome") == "ACCEPTED":
                    executions.append({
                        "packageId": pkg_id,
                        "actionId": res["actionId"],
                        "action": res["action"],
                        "receiptNonce": res.get("receiptNonce", ""),
                        "facts": prop["facts"],
                        "evidenceRefs": prop["evidenceRefs"]
                    })

            now_iso = now_iso_utc()
            receipt_artifact = {
                "artifactId": f"receipts-{stored_batch_id}",
                "name": "invoice-action-receipts",
                "parts": [
                    {
                        "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
                        "data": {
                            "batchId": stored_batch_id,
                            "executions": executions
                        }
                    }
                ]
            }

            task["artifacts"].append(receipt_artifact)
            task["status"] = {
                "state": "TASK_STATE_COMPLETED",
                "timestamp": now_iso
            }
            task["state"] = "TASK_STATE_COMPLETED"
            task["updatedAt"] = now_iso
            task.setdefault("history", []).append(message)

            save_task(task, principal, stored_batch_id, stored_proposals)
            save_idempotency_record(principal, message_id, msg_hash, task_id, {"task": task})

            return a2a_response({"task": task})

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported part mediaType: {media_type}"
        )

# ----------------- Task Read Route -----------------

@app.get("/tasks/{id}")
@app.get("/a2a/tasks/{id}")
async def get_task_endpoint(id: str, request: Request):
    principal = authenticate_and_validate(request)
    task = get_task(id, principal)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found.")

    history_length_param = request.query_params.get("historyLength")
    if history_length_param is not None:
        try:
            hl = int(history_length_param)
            task_copy = dict(task)
            hist = task_copy.get("history", [])
            task_copy["history"] = hist[-hl:] if hl > 0 else []
            return a2a_response(task_copy)
        except ValueError:
            pass

    return a2a_response(task)

# ----------------- Task Listing Route -----------------

@app.get("/tasks")
@app.get("/a2a/tasks")
async def list_tasks_endpoint(request: Request):
    principal = authenticate_and_validate(request)
    context_id = request.query_params.get("contextId")
    status_filter = request.query_params.get("status")

    tasks = list_tasks(principal, context_id=context_id, status=status_filter)
    return a2a_response({"tasks": tasks})

# ----------------- Task Cancellation Route -----------------

@app.post("/tasks/{id}:cancel")
@app.post("/a2a/tasks/{id}:cancel")
async def cancel_task_endpoint(id: str, request: Request):
    principal = authenticate_and_validate(request)
    
    task_lock = await get_task_lock(id)
    async with task_lock:
        task = get_task(id, principal)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found.")

        curr_state = task.get("status", {}).get("state")
        
        # If already COMPLETED: cancel returns 409 Conflict
        if curr_state == "TASK_STATE_COMPLETED":
            return a2a_response({
                "error": "TASK_TERMINAL_CONFLICT",
                "message": "Task is already completed and cannot be canceled."
            }, status_code=409)

        # If already CANCELED: return task
        if curr_state == "TASK_STATE_CANCELED":
            return a2a_response(task)

        # Transition nonterminal task to CANCELED
        now_iso = now_iso_utc()
        task["status"] = {
            "state": "TASK_STATE_CANCELED",
            "timestamp": now_iso
        }
        task["state"] = "TASK_STATE_CANCELED"
        task["updatedAt"] = now_iso

        from storage import get_db
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT batch_id, proposals_json FROM tasks WHERE task_id = ?", (id,))
        row = cursor.fetchone()
        conn.close()

        batch_id = row["batch_id"] if row else ""
        proposals = json.loads(row["proposals_json"]) if row else []
        save_task(task, principal, batch_id, proposals)

        return a2a_response(task)

if __name__ == "__main__":
    init_db()
    print("Starting A2A Invoice Agent on port 8000...")
    sys.stdout.flush()
    uvicorn.run(app, host="0.0.0.0", port=8000)
