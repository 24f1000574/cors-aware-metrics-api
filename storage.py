import sqlite3
import json
import hashlib
from typing import Optional, Dict, Any, List

DB_PATH = "invoice_agent.db"

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    
    # Tasks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            context_id TEXT,
            owner_principal TEXT,
            batch_id TEXT,
            state TEXT,
            proposals_json TEXT,
            task_json TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_owner ON tasks(owner_principal)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_ctx ON tasks(context_id)')
    
    # Idempotency table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS idempotency (
            principal TEXT,
            message_id TEXT,
            message_hash TEXT,
            task_id TEXT,
            response_json TEXT,
            PRIMARY KEY (principal, message_id)
        )
    ''')
    
    # Decision cache (canonical package content hash -> proposal facts & decision)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS decision_cache (
            canonical_pkg_hash TEXT PRIMARY KEY,
            action TEXT,
            facts_json TEXT,
            evidence_refs_json TEXT,
            rationale TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def canonical_hash(obj: Any) -> str:
    canonical_str = json.dumps(obj, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

def get_idempotency_record(principal: str, message_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT message_hash, task_id, response_json FROM idempotency WHERE principal = ? AND message_id = ?",
        (principal, message_id)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "message_hash": row["message_hash"],
            "task_id": row["task_id"],
            "response": json.loads(row["response_json"]) if row["response_json"] else None
        }
    return None

def save_idempotency_record(principal: str, message_id: str, message_hash: str, task_id: str, response: Dict[str, Any]):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT OR REPLACE INTO idempotency (principal, message_id, message_hash, task_id, response_json)
           VALUES (?, ?, ?, ?, ?)''',
        (principal, message_id, message_hash, task_id, json.dumps(response))
    )
    conn.commit()
    conn.close()

def get_task(task_id: str, principal: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT task_json, owner_principal FROM tasks WHERE task_id = ?",
        (task_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    # User isolation: return None if principal does not match
    if row["owner_principal"] != principal:
        return None
    return json.loads(row["task_json"])

def list_tasks(principal: str, context_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT task_json, state FROM tasks WHERE owner_principal = ?"
    params = [principal]
    if context_id:
        query += " AND context_id = ?"
        params.append(context_id)
    if status:
        query += " AND state = ?"
        params.append(status)
    query += " ORDER BY created_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(r["task_json"]) for r in rows]

def save_task(task: Dict[str, Any], principal: str, batch_id: str, proposals: List[Dict[str, Any]]):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT OR REPLACE INTO tasks (task_id, context_id, owner_principal, batch_id, state, proposals_json, task_json, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            task["id"],
            task.get("contextId", ""),
            principal,
            batch_id,
            task.get("status", {}).get("state", "TASK_STATE_INPUT_REQUIRED"),
            json.dumps(proposals),
            json.dumps(task),
            task.get("createdAt", ""),
            task.get("updatedAt", "")
        )
    )
    conn.commit()
    conn.close()

def get_cached_decision(canonical_pkg_hash: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT action, facts_json, evidence_refs_json, rationale FROM decision_cache WHERE canonical_pkg_hash = ?",
        (canonical_pkg_hash,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "action": row["action"],
            "facts": json.loads(row["facts_json"]),
            "evidenceRefs": json.loads(row["evidence_refs_json"]),
            "rationale": row["rationale"]
        }
    return None

def save_cached_decision(canonical_pkg_hash: str, action: str, facts: Dict[str, Any], evidence_refs: List[str], rationale: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT OR REPLACE INTO decision_cache (canonical_pkg_hash, action, facts_json, evidence_refs_json, rationale)
           VALUES (?, ?, ?, ?, ?)''',
        (canonical_pkg_hash, action, json.dumps(facts), json.dumps(evidence_refs), rationale)
    )
    conn.commit()
    conn.close()
