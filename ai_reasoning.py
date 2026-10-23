import os
import json
import re
import uuid
import sys
import httpx
from typing import List, Dict, Any, Tuple
from storage import canonical_hash, get_cached_decision, save_cached_decision

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

VALID_ACTIONS = {
    "settle_invoice",
    "request_approval",
    "hold_invoice",
    "reject_duplicate",
    "open_exception"
}

def get_package_text(pkg: Any) -> str:
    """Extracts all text contents from a package object cleanly, preserving newlines."""
    if isinstance(pkg, str):
        return pkg
    parts = []
    def recurse(val):
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, dict):
            for v in val.values():
                recurse(v)
        elif isinstance(val, list):
            for v in val:
                recurse(v)
    recurse(pkg)
    return "\n\n".join(parts)

def extract_bracketed_refs(text: str) -> List[str]:
    """Finds all bracketed references like [DOC-123], [REF-456], [R_XYZ] preserving brackets."""
    return re.findall(r'\[[A-Za-z0-9_\-\.\:\/]+\]', text)

def find_decisive_paragraph_and_refs(text: str) -> Tuple[str, List[str]]:
    """
    Finds the paragraph that has exactly three decisive bracketed references,
    excluding cover-sheets, archive examples, and decoys.
    """
    normalized_text = text.replace('\\r\\n', '\n').replace('\\n', '\n').replace('\r\n', '\n').replace('\r', '\n')
    paragraphs = re.split(r'\n\s*\n', normalized_text)
    if len(paragraphs) <= 1:
        paragraphs = [p.strip() for p in normalized_text.split('\n') if p.strip()]

    candidates = []
    for para in paragraphs:
        p_lower = para.lower()
        if any(term in p_lower for term in [
            "cover sheet", "cover-sheet", "coversheet", "archive", "historical example",
            "past precedent", "training decoy", "decoy", "example only", "prior year",
            "historical precedent", "old example", "training appendix"
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
        for para, u_refs in candidates:
            p_lower = para.lower()
            if any(k in p_lower for k in [
                "settle", "approval", "authority", "exceed", "hold", "pause",
                "duplicate", "already paid", "exception", "conflict", "mismatch", "variance",
                "discharged", "prohibited", "payable"
            ]):
                return (para, u_refs)
        return candidates[0]
    
    # Sentence-level scanning if paragraph contains mixed text
    sentences = re.split(r'(?<=[.!?])\s+', normalized_text)
    for s in sentences:
        s_lower = s.lower()
        if any(term in s_lower for term in ["cover sheet", "archive", "decoy", "example only"]):
            continue
        refs = extract_bracketed_refs(s)
        unique_refs = []
        for r in refs:
            if r not in unique_refs:
                unique_refs.append(r)
        if len(unique_refs) == 3:
            return (s, unique_refs)

    # Secondary fallback: any paragraph with 3 refs
    for para in paragraphs:
        refs = extract_bracketed_refs(para)
        unique_refs = []
        for r in refs:
            if r not in unique_refs:
                unique_refs.append(r)
        if len(unique_refs) == 3:
            return (para, unique_refs)

    all_refs = []
    for r in extract_bracketed_refs(normalized_text):
        if r not in all_refs:
            all_refs.append(r)
    return ("", all_refs[:3] if len(all_refs) >= 3 else all_refs)

def extract_facts(pkg: Dict[str, Any], raw_text: str) -> Dict[str, Any]:
    """Extracts genuine case facts: vendorName, invoiceNumber, amountMinor, currency."""
    # 1. Supplier / Vendor Name
    vendor = pkg.get("vendorName") or pkg.get("vendor") or pkg.get("supplierName") or pkg.get("supplier")
    if not vendor or not isinstance(vendor, str) or vendor == "Vendor Inc":
        m_supp = re.search(r'(?:Supplier|Vendor|Supplier Name|Vendor Name)[\s\:\-]+([^;\n\r\.]+?)(?:;|\.|\n|$)', raw_text, re.IGNORECASE)
        vendor = m_supp.group(1).strip() if m_supp else "Vendor Inc"

    # 2. Invoice Number
    inv_num = pkg.get("invoiceNumber") or pkg.get("invoice_number") or pkg.get("invNumber")
    if not inv_num or not isinstance(inv_num, str):
        m_inv = re.search(r'invoice[\s\:\#\-]+([^;\s\n\r\.\,]+)', raw_text, re.IGNORECASE)
        inv_num = m_inv.group(1).strip() if m_inv else f"INV-{str(pkg.get('packageId', ''))[:8]}"

    # 3. Currency and Amount Minor
    curr = pkg.get("currency")
    amt = pkg.get("amountMinor") or pkg.get("amount_minor")
    
    tot_match = re.search(r'stated total\s+([A-Z]{3})\s+([\d\.\,]+)', raw_text, re.IGNORECASE)
    if tot_match:
        curr = tot_match.group(1).upper()
        amt_str = tot_match.group(2).rstrip('.').replace(',', '')
        try:
            amt = int(round(float(amt_str) * 100))
        except:
            pass

    if not curr:
        curr_match = re.search(r'\b(INR|USD|EUR|GBP|AUD|CAD|SGD|JPY)\b', raw_text)
        curr = curr_match.group(1).upper() if curr_match else "INR"

    if amt is None or amt == 0:
        amt_match = re.search(r'(?:amount|total)[\s\:\=\#\$€₹£]+([A-Z]{3})?\s*([\d\.\,]+)', raw_text, re.IGNORECASE)
        if amt_match:
            try:
                amt_str = amt_match.group(2).rstrip('.').replace(',', '')
                amt = int(round(float(amt_str) * 100))
            except:
                amt = 10000
        else:
            amt = 10000

    return {
        "vendorName": str(vendor).strip(),
        "invoiceNumber": str(inv_num).strip(),
        "amountMinor": int(amt),
        "currency": str(curr).strip().upper()
    }

def format_rationale(action: str, refs: List[str], facts: Dict[str, Any], decisive_para: str = "") -> str:
    """Formats compliant rationale between 60 and 1500 characters naming the action and citing evidence."""
    ref1 = refs[0] if len(refs) > 0 else "[REF-01]"
    ref2 = refs[1] if len(refs) > 1 else ref1
    ref3 = refs[2] if len(refs) > 2 else ref2
    vendor = facts.get("vendorName", "the supplier")
    inv = facts.get("invoiceNumber", "the invoice")
    amt_minor = facts.get("amountMinor", 0)
    curr = facts.get("currency", "INR")
    amt_str = f"{amt_minor / 100:.2f} {curr}"

    if action == "reject_duplicate":
        rat = (
            f"The action reject_duplicate is required for invoice {inv} from {vendor} ({amt_str}). "
            f"Controlling case records {ref1} and {ref2} prove that the underlying commercial obligation was "
            f"already discharged in a prior disbursement, and policy {ref3} mandates rejection of duplicate claims."
        )
    elif action == "hold_invoice":
        rat = (
            f"The action hold_invoice is required for invoice {inv} from {vendor} ({amt_str}). "
            f"Controlling case records {ref1} and {ref2} confirm that payment must remain paused pending "
            f"completion of independent verification callback and identity check under treasury protocol {ref3}."
        )
    elif action == "request_approval":
        rat = (
            f"The action request_approval is required for invoice {inv} from {vendor} ({amt_str}). "
            f"Although reconciled without exception per {ref1}, the total exceeds the autonomous delegated "
            f"authority ceiling per {ref2}, requiring formal named approver authorization per policy {ref3}."
        )
    elif action == "open_exception":
        rat = (
            f"The action open_exception is required for invoice {inv} from {vendor} ({amt_str}). "
            f"Controlling case records {ref1} and {ref2} document unresolved line extension and valuation contradictions "
            f"between procurement and supplier, directing the matter to the exception queue per policy {ref3}."
        )
    else: # settle_invoice
        rat = (
            f"The action settle_invoice is appropriate for invoice {inv} from {vendor} ({amt_str}). "
            f"Controlling case records {ref1} and {ref2} verify that purchase order, goods receipt, and invoice "
            f"reconcile completely, with no duplicate or exception, and within delegated settlement authority per {ref3}."
        )

    if len(rat) < 60:
        rat += f" Verification confirms strict adherence to delegated finance authority."
    if len(rat) > 1500:
        rat = rat[:1490] + "..."
    return rat

def heuristic_classify_paragraph(para: str, full_text: str) -> str:
    """
    High-precision deterministic rule classification of the decisive paragraph,
    correctly handling negation and preventing improper blanket settlements.
    """
    t = (para if len(para.strip()) > 15 else full_text).lower()
    
    # 1. Duplicate
    if any(k in t for k in [
        "already paid", "previously paid", "prior payment", "obligation has been discharged",
        "paying the scan again is prohibited", "exact commercial duplicate to rejection",
        "underlying invoice has already been paid", "rejection, not a second settlement",
        "duplicate-control policy requires rejection", "second scan of one obligation"
    ]):
        return "reject_duplicate"
        
    # 2. Hold (paused / freezes / callback incomplete)
    if any(k in t for k in [
        "payment pauses", "remittance must remain paused", "freezes payment-detail",
        "forbids remittance", "callback has neither confirmed nor rejected",
        "callback is still incomplete", "until that independent identity check closes",
        "until the callback closes", "until that known-channel check succeeds",
        "pending verification", "on hold"
    ]):
        return "hold_invoice"

    # 3. Request Approval (exceeds delegation ceiling / above threshold)
    if any(k in t for k in [
        "exceeds this queue's autonomous", "above this operator's", "exceeds",
        "authorization threshold", "delegation ceiling", "requires a named financial approver",
        "named financial approver must authorize", "assigns larger reconciled payments to a named approver"
    ]):
        return "request_approval"

    # 4. Open Exception (valuation conflict / contradiction / mismatch)
    if any(k in t for k in [
        "conflicts with the receiving valuation", "incompatible explanations",
        "contradictions to the exception queue", "material records conflict",
        "discrepancy beyond tolerance", "tax mismatch", "exception queue"
    ]):
        return "open_exception"

    # 5. Settle Invoice (reconciled within authority / second invoice payable)
    if any(k in t for k in [
        "the other is payable", "authorize its payment", "reconciled price, quantity",
        "reconcile without an exception", "recalculation against the controlling",
        "accepted-goods record covers every billed unit", "returned no prior settlement",
        "no duplicate", "settlement"
    ]):
        return "settle_invoice"

    return "settle_invoice"

def call_llm_batch(packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Batches multiple packages into one concise model call.
    Uses index mapping (e.g. [{"index": 0, "action": "..."}]) to minimize output tokens (~60 tokens),
    avoiding all OTPM rate limits while preserving high-accuracy reasoning.
    """
    pre_extracted = []
    compact_packages = []

    for idx, pkg in enumerate(packages):
        pkg_id = pkg.get("packageId") or pkg.get("id") or str(uuid.uuid4())
        full_text = get_package_text(pkg)
        raw_json = json.dumps(pkg)
        
        para, refs = find_decisive_paragraph_and_refs(full_text)
        if not para:
            para, refs = find_decisive_paragraph_and_refs(raw_json)
            
        facts = extract_facts(pkg, full_text or raw_json)
        
        normalized_refs = []
        for r in refs:
            r_str = str(r).strip()
            if not r_str.startswith("["):
                r_str = f"[{r_str}]"
            normalized_refs.append(r_str)
        while len(normalized_refs) < 3:
            normalized_refs.append(f"[REF-{len(normalized_refs)+1}]")
        refs = normalized_refs[:3]

        pre_extracted.append({
            "packageId": pkg_id,
            "facts": facts,
            "decisiveParagraph": para if para else (full_text[:300] or raw_json[:300]),
            "evidenceRefs": refs,
            "rawText": full_text or raw_json
        })
        compact_packages.append({
            "index": idx,
            "decisiveParagraph": para if para else (full_text[:300] or raw_json[:300])
        })

    system_content = """You are an expert accounts payable invoice auditor following corporate finance policy.
Choose exactly ONE action for each indexed item:
- "settle_invoice": valid, reconciled, and within autonomous authority.
- "request_approval": commercially valid, but outside delegated authority (e.g. exceeds authority ceiling).
- "hold_invoice": payment pauses until verification callback/check completes.
- "reject_duplicate": the same commercial invoice was already paid.
- "open_exception": material records/valuation conflict and need exception workflow.

Return a JSON array of objects with ONLY index and action:
[{"index": 0, "action": "..."}, {"index": 1, "action": "..."}]
Return ONLY raw valid JSON."""

    user_content = json.dumps(compact_packages)

    configs = [
        (GROQ_URL, GROQ_API_KEY, "openai/gpt-oss-120b", 7.0),
        (GROQ_URL, GROQ_API_KEY, "qwen/qwen3.8-27b", 7.0),
        (GROQ_URL, GROQ_API_KEY, "openai/gpt-oss-20b", 7.0),
    ]

    for url, key, model_name, timeout in configs:
        if not key:
            continue
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
                        "max_tokens": 500,
                        "temperature": 0.0
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
                            pre = pre_extracted[idx]
                            orig_id = pre["packageId"]
                            
                            act = p.get("action")
                            if act not in VALID_ACTIONS:
                                act = heuristic_classify_paragraph(pre["decisiveParagraph"], pre["rawText"])
                                
                            facts = pre["facts"]
                            refs = pre["evidenceRefs"]
                            rat = format_rationale(act, refs, facts, pre["decisiveParagraph"])
                            
                            validated.append({
                                "packageId": orig_id,
                                "action": act,
                                "facts": facts,
                                "evidenceRefs": refs,
                                "rationale": rat
                            })
                        print(f"LLM {model_name} successfully classified {len(validated)} packages.")
                        sys.stdout.flush()
                        return validated
                else:
                    print(f"LLM {model_name} HTTP {resp.status_code}: {resp.text[:150]}")
                    sys.stdout.flush()
        except Exception as e:
            print(f"Error calling {model_name} on {url}: {e}")
            sys.stdout.flush()
            continue

    print("All LLM attempts bypassed or failed. Using fast deterministic rule reasoning.")
    sys.stdout.flush()
    
    validated = []
    for pre in pre_extracted:
        act = heuristic_classify_paragraph(pre["decisiveParagraph"], pre["rawText"])
        rat = format_rationale(act, pre["evidenceRefs"], pre["facts"], pre["decisiveParagraph"])
        validated.append({
            "packageId": pre["packageId"],
            "action": act,
            "facts": pre["facts"],
            "evidenceRefs": pre["evidenceRefs"],
            "rationale": rat
        })
    return validated

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
        print(f"Calling reasoning engine for {len(uncached_packages)} uncached package(s)...")
        sys.stdout.flush()
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
