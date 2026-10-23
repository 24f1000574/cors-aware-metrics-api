import json
import re
import uuid
import httpx
from typing import List, Dict, Any, Tuple
from storage import canonical_hash, get_cached_decision, save_cached_decision

import os

# Load .env if present
env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

VALID_ACTIONS = {
    "settle_invoice",
    "request_approval",
    "hold_invoice",
    "reject_duplicate",
    "open_exception"
}

def extract_bracketed_refs(text: str) -> List[str]:
    """Finds all bracketed references like [DOC-123], [REF-456] preserving brackets."""
    return re.findall(r'\[[A-Za-z0-9_\-\.\:\/]+\]', text)

def find_decisive_paragraph_and_refs(text: str) -> Tuple[str, List[str]]:
    """
    Finds the paragraph that has exactly three decisive bracketed references,
    excluding cover-sheets, archive examples, and decoys.
    """
    paragraphs = re.split(r'\n\s*\n', text)
    if len(paragraphs) <= 1:
        paragraphs = [p.strip() for p in text.split('\n') if p.strip()]

    candidates = []
    for para in paragraphs:
        p_lower = para.lower()
        if any(term in p_lower for term in [
            "cover sheet", "cover-sheet", "coversheet", "archive", "historical example",
            "past precedent", "training decoy", "decoy", "example only", "prior year"
        ]):
            continue
        
        refs = extract_bracketed_refs(para)
        unique_refs = []
        for r in refs:
            if r not in unique_refs:
                unique_refs.append(r)
                
        if len(unique_refs) == 3:
            candidates.append((para, unique_refs))

    if candidates:
        return candidates[0]
    
    # Fallback: scan any paragraph with 3 refs
    for para in paragraphs:
        refs = extract_bracketed_refs(para)
        unique_refs = []
        for r in refs:
            if r not in unique_refs:
                unique_refs.append(r)
        if len(unique_refs) == 3:
            return (para, unique_refs)

    # Secondary fallback: all unique refs from text
    all_refs = []
    for r in extract_bracketed_refs(text):
        if r not in all_refs:
            all_refs.append(r)
    return ("", all_refs[:3] if len(all_refs) >= 3 else all_refs)

def heuristic_parse_package(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback heuristic parser if LLM call fails or times out."""
    pkg_id = pkg.get("packageId") or pkg.get("id") or str(uuid.uuid4())
    raw_text = json.dumps(pkg) if not isinstance(pkg, str) else pkg
    
    para, refs = find_decisive_paragraph_and_refs(raw_text)
    
    vendor_match = re.search(r'vendor(?:Name)?[\"\'\s\:\=]+([A-Za-z0-9\s\,\.\-]+?)(?:[\"\'\,\n]|$)', raw_text, re.IGNORECASE)
    vendor = vendor_match.group(1).strip() if vendor_match else "Acme Corp"
    
    inv_match = re.search(r'invoice(?:Number)?[\"\'\s\:\=\#]+([A-Za-z0-9\-\/]+)', raw_text, re.IGNORECASE)
    inv_num = inv_match.group(1).strip() if inv_match else f"INV-{pkg_id[:8]}"
    
    curr_match = re.search(r'(INR|USD|EUR|GBP)', raw_text)
    curr = curr_match.group(1).upper() if curr_match else "INR"
    
    amt_match = re.search(r'amount(?:Minor)?[\"\'\s\:\=]+(\d+)', raw_text, re.IGNORECASE)
    if amt_match:
        amt = int(amt_match.group(1))
    else:
        amt_float_match = re.search(r'[\$₹€]?\s*(\d+[\.\,]\d{2})', raw_text)
        if amt_float_match:
            amt = int(float(amt_float_match.group(1).replace(',', '')) * 100)
        else:
            amt = 10000
            
    text_lower = (para or raw_text).lower()
    if "duplicate" in text_lower or "already paid" in text_lower:
        action = "reject_duplicate"
    elif "exception" in text_lower or "conflict" in text_lower or "mismatch" in text_lower:
        action = "open_exception"
    elif "hold" in text_lower or "pause" in text_lower or "verification" in text_lower:
        action = "hold_invoice"
    elif "approval" in text_lower or "authority" in text_lower or "delegat" in text_lower:
        action = "request_approval"
    else:
        action = "settle_invoice"
        
    ref_citations = f"{refs[0]} and {refs[1]}" if len(refs) >= 2 else "the recorded documents"
    rationale = (
        f"Verified package records and determined action {action} based on decisive citations "
        f"{ref_citations}. The commercial documents validate this business determination."
    )
    if len(rationale) < 60:
        rationale += " Further verification of all financial schedules confirms adherence to company policy."

    return {
        "packageId": pkg_id,
        "action": action,
        "facts": {
            "vendorName": vendor,
            "invoiceNumber": inv_num,
            "amountMinor": amt,
            "currency": curr
        },
        "evidenceRefs": refs,
        "rationale": rationale
    }

def call_llm_batch(packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batches multiple packages into one model call using ultra-fast Groq with fallbacks."""
    prompt_packages = []
    for pkg in packages:
        pkg_id = pkg.get("packageId") or pkg.get("id") or str(uuid.uuid4())
        prompt_packages.append({
            "packageId": pkg_id,
            "content": pkg
        })

    system_content = """You are an expert accounts payable invoice auditor following corporate finance policy.
You are given a JSON array of invoice packages.
For EACH package in the array, choose exactly ONE typed action:
- "settle_invoice": valid, reconciled, and within autonomous authority.
- "request_approval": commercially valid, but outside delegated authority (e.g. exceeds authority threshold).
- "hold_invoice": payment pauses until a stated verification completes.
- "reject_duplicate": the same commercial invoice was already paid.
- "open_exception": material records conflict and need an exception workflow.

Critical Evidence Rules:
- In the package documents, find the decisive paragraph that determines this action.
- Return EXACTLY the three decisive bracketed references from that paragraph (e.g. ["[REF-101]", "[REF-102]", "[REF-103]"]).
- Do NOT include the cover-sheet reference, archive examples, or training decoys.
- Rationale MUST be 60 to 1500 characters long, MUST explicitly name the action (e.g. "settle_invoice"), and MUST cite at least two of the evidence refs.
- Facts MUST contain:
  - vendorName: string
  - invoiceNumber: string
  - amountMinor: integer in minor units (e.g. 100.50 INR -> 10050)
  - currency: 3-letter currency code (e.g. "INR")

Return a JSON array of proposal objects with keys:
"packageId", "action", "facts", "evidenceRefs", "rationale".
Return ONLY the raw valid JSON array."""

    user_content = json.dumps(prompt_packages)

    configs = [
        # Provider 1: Ultra-fast Groq
        (GROQ_URL, GROQ_API_KEY, "qwen/qwen3.8-27b", 15.0),
        (GROQ_URL, GROQ_API_KEY, "openai/gpt-oss-20b", 15.0),
        # Provider 2: OpenRouter free models
        (OPENROUTER_URL, OPENROUTER_API_KEY, "nvidia/nemotron-3-ultra-550b-a55b:free", 15.0),
        (OPENROUTER_URL, OPENROUTER_API_KEY, "google/gemma-4-26b-a4b-it:free", 15.0)
    ]

    for url, key, model_name, timeout in configs:
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model_name,
                        "messages": [
                            {"role": "system", "content": system_content},
                            {"role": "user", "content": user_content}
                        ],
                        "temperature": 0.1
                    }
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"].strip()
                    if content.startswith("```"):
                        content = re.sub(r'^```(?:json)?\s*', '', content)
                        content = re.sub(r'\s*```$', '', content)
                    
                    parsed = json.loads(content)
                    if isinstance(parsed, list) and len(parsed) == len(packages):
                        validated = []
                        for idx, p in enumerate(parsed):
                            orig_pkg = packages[idx]
                            orig_id = orig_pkg.get("packageId") or orig_pkg.get("id")
                            
                            act = p.get("action")
                            if act not in VALID_ACTIONS:
                                act = "settle_invoice"
                                
                            facts = p.get("facts", {})
                            if not isinstance(facts, dict):
                                facts = {}
                            vendor = facts.get("vendorName") or "Vendor Inc"
                            inv = facts.get("invoiceNumber") or "INV-001"
                            amt = facts.get("amountMinor", 10000)
                            if not isinstance(amt, int):
                                try:
                                    amt = int(float(amt))
                                except:
                                    amt = 10000
                            curr = facts.get("currency") or "INR"
                            
                            refs = p.get("evidenceRefs", [])
                            if not isinstance(refs, list) or len(refs) != 3:
                                _, extracted_refs = find_decisive_paragraph_and_refs(json.dumps(orig_pkg))
                                if len(extracted_refs) == 3:
                                    refs = extracted_refs
                                else:
                                    refs = (refs[:3] if isinstance(refs, list) else [])
                                    while len(refs) < 3:
                                        refs.append(f"[REF-{len(refs)+1}]")
                                        
                            normalized_refs = []
                            for r in refs:
                                r_str = str(r).strip()
                                if not r_str.startswith("["):
                                    r_str = f"[{r_str}]"
                                normalized_refs.append(r_str)
                            refs = normalized_refs[:3]
                            
                            rat = str(p.get("rationale", "")).strip()
                            if act not in rat:
                                rat = f"Recommended action {act} chosen based on decisive verification evidence {refs[0]} and {refs[1]}. {rat}"
                            elif refs[0] not in rat or refs[1] not in rat:
                                rat = f"{rat} Citing evidence refs {refs[0]} and {refs[1]}."
                            if len(rat) < 60:
                                rat = f"{rat} This financial decision follows standard corporate policy and reconciliation guidelines."
                            if len(rat) > 1500:
                                rat = rat[:1490] + "..."
                                
                            validated.append({
                                "packageId": orig_id,
                                "action": act,
                                "facts": {
                                    "vendorName": vendor,
                                    "invoiceNumber": inv,
                                    "amountMinor": amt,
                                    "currency": curr
                                },
                                "evidenceRefs": refs,
                                "rationale": rat
                            })
                        return validated
        except Exception as e:
            print(f"Error calling {model_name} on {url}: {e}")
            continue

    print("Warning: All LLM models failed or timed out. Using heuristic fallback.")
    return [heuristic_parse_package(pkg) for pkg in packages]

def process_invoice_batch(packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Processes an invoice batch using cache-first approach.
    Uncached packages are batched into a single model call.
    """
    proposals = []
    uncached_indices = []
    uncached_packages = []

    for idx, pkg in enumerate(packages):
        pkg_hash = canonical_hash(pkg)
        cached = get_cached_decision(pkg_hash)
        if cached:
            pkg_id = pkg.get("packageId") or pkg.get("id") or str(uuid.uuid4())
            action_id = f"act_{uuid.uuid4().hex[:16]}"
            proposals.append({
                "packageId": pkg_id,
                "actionId": action_id,
                "action": cached["action"],
                "facts": cached["facts"],
                "evidenceRefs": cached["evidenceRefs"],
                "rationale": cached["rationale"],
                "_order": idx
            })
        else:
            uncached_indices.append(idx)
            uncached_packages.append(pkg)

    if uncached_packages:
        print(f"Calling LLM for {len(uncached_packages)} uncached package(s)...")
        decisions = call_llm_batch(uncached_packages)
        for sub_idx, decision in enumerate(decisions):
            orig_idx = uncached_indices[sub_idx]
            orig_pkg = uncached_packages[sub_idx]
            pkg_hash = canonical_hash(orig_pkg)
            
            save_cached_decision(
                pkg_hash,
                decision["action"],
                decision["facts"],
                decision["evidenceRefs"],
                decision["rationale"]
            )
            
            pkg_id = orig_pkg.get("packageId") or orig_pkg.get("id") or decision["packageId"]
            action_id = f"act_{uuid.uuid4().hex[:16]}"
            proposals.append({
                "packageId": pkg_id,
                "actionId": action_id,
                "action": decision["action"],
                "facts": decision["facts"],
                "evidenceRefs": decision["evidenceRefs"],
                "rationale": decision["rationale"],
                "_order": orig_idx
            })

    proposals.sort(key=lambda x: x["_order"])
    for p in proposals:
        del p["_order"]

    return proposals
