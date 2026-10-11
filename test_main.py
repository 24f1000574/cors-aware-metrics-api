import time
import base64
import random
import re
import collections
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from starlette.testclient import TestClient
import main
from main import app, USER_EMAIL, ALLOWED_ORIGIN_STATS

client = TestClient(app)

# Generate temporary test RSA key pair to test verification behavior
test_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
test_pub_key = test_priv_key.public_key()
test_pub_pem = test_pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")
test_priv_pem = test_priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")


def parse_http_requests_total(metrics_text: str) -> float:
    match = re.search(r"^http_requests_total(?:\s*\{[^}]*\})?\s+([0-9.]+)", metrics_text, re.MULTILINE)
    assert match is not None, f"Could not find http_requests_total in metrics output:\n{metrics_text}"
    return float(match.group(1))


def test_question_8_observability():
    print("--- Running Question 8 (Observability, Health & Structured Logs) Tests ---")

    # 1. Baseline metrics reading
    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    assert "http_requests_total" in metrics_res.text
    baseline = parse_http_requests_total(metrics_res.text)
    print(f"Baseline http_requests_total: {baseline}")

    # 2. Random calls to /work?n=K
    num_calls = random.randint(3, 6)
    for i in range(num_calls):
        k = random.randint(1, 50)
        res = client.get(f"/work?n={k}")
        assert res.status_code == 200
        data = res.json()
        assert data["email"] == USER_EMAIL
        assert data["done"] == k

    print(f"Made {num_calls} calls to /work?n=K successfully.")

    # 3. Read metrics again and verify counter increment
    metrics_res2 = client.get("/metrics")
    assert metrics_res2.status_code == 200
    counter_after = parse_http_requests_total(metrics_res2.text)
    delta = counter_after - baseline
    print(f"New http_requests_total: {counter_after}, delta: {delta} (expected >= {num_calls})")
    assert delta >= num_calls, f"Counter only increased by {delta}, expected at least {num_calls}"

    # 4. Check /healthz
    healthz_res = client.get("/healthz")
    assert healthz_res.status_code == 200
    h_data = healthz_res.json()
    assert h_data.get("status") == "ok"
    uptime = h_data.get("uptime_s")
    assert isinstance(uptime, (int, float))
    assert uptime >= 0.0
    print(f"/healthz PASSED: status={h_data['status']}, uptime_s={uptime}")

    # 5. Check /logs/tail
    tail_res = client.get("/logs/tail?limit=10")
    assert tail_res.status_code == 200
    logs = tail_res.json()
    assert isinstance(logs, list)
    assert len(logs) > 0

    required_keys = {"level", "ts", "path", "request_id"}
    has_work_entry = False
    for entry in logs:
        assert isinstance(entry, dict)
        for key in required_keys:
            assert key in entry, f"Missing key '{key}' in log entry: {entry}"
            assert entry[key] is not None and str(entry[key]).strip() != ""
        if "/work" in entry["path"]:
            has_work_entry = True

    assert has_work_entry, f"No entry with path containing '/work' found in logs tail: {logs}"
    print(f"/logs/tail PASSED: returned {len(logs)} entries, found /work entry.")

    # 6. Test with varying limit parameter
    tail_limit_3 = client.get("/logs/tail?limit=3")
    assert tail_limit_3.status_code == 200
    assert len(tail_limit_3.json()) <= 3

    print("Question 8 tests PASSED successfully!\n")


def test_question_3_stats():
    print("--- Running Question 3 (Stats & CORS) Tests ---")
    res = client.options("/stats", headers={
        "Origin": ALLOWED_ORIGIN_STATS,
        "Access-Control-Request-Method": "GET",
    })
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN_STATS
    assert "x-request-id" in res.headers
    assert "x-process-time" in res.headers

    res = client.options("/stats", headers={
        "Origin": "https://evil.attacker.com",
        "Access-Control-Request-Method": "GET",
    })
    assert "access-control-allow-origin" not in res.headers
    assert "x-request-id" in res.headers
    assert "x-process-time" in res.headers

    res = client.get("/stats?values=10,20,30,40", headers={"Origin": ALLOWED_ORIGIN_STATS})
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN_STATS
    data = res.json()
    assert data["email"] == USER_EMAIL
    assert data["count"] == 4
    assert data["sum"] == 100
    assert data["min"] == 10
    assert data["max"] == 40
    assert abs(data["mean"] - 25.0) < 0.01

    batch = [random.randint(-1000, 1000) for _ in range(50)]
    res = client.get(f"/stats?values={','.join(map(str, batch))}")
    assert res.status_code == 200
    assert "access-control-allow-origin" not in res.headers
    data = res.json()
    assert data["count"] == len(batch)
    assert data["sum"] == sum(batch)
    print("Question 3 tests passed!")


def test_question_4_verify():
    print("--- Running Question 4 (Token Verification) Tests ---")
    orig_key = main.IDP_PUBLIC_KEY
    main.IDP_PUBLIC_KEY = test_pub_pem
    try:
        now = int(time.time())

        valid_payload = {
            "iss": "https://idp.exam.local",
            "aud": "tds-e8pdjl8x.apps.exam.local",
            "sub": "user-abc-123",
            "email": "test-user@exam.local",
            "exp": now + 3600,
            "iat": now,
        }
        valid_tok = jwt.encode(valid_payload, test_priv_pem, algorithm="RS256")
        res = client.post("/verify", json={"token": valid_tok})
        assert res.status_code == 200
        assert "x-request-id" in res.headers
        assert "x-process-time" in res.headers
        data = res.json()
        assert data["valid"] is True
        assert data["sub"] == "user-abc-123"
        assert data["email"] == "test-user@exam.local"
        assert data["aud"] == "tds-e8pdjl8x.apps.exam.local"

        expired_payload = {
            "iss": "https://idp.exam.local",
            "aud": "tds-e8pdjl8x.apps.exam.local",
            "sub": "user-abc-123",
            "email": "test-user@exam.local",
            "exp": now - 3600,
        }
        expired_tok = jwt.encode(expired_payload, test_priv_pem, algorithm="RS256")
        res = client.post("/verify", json={"token": expired_tok})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        wrong_aud_payload = {
            "iss": "https://idp.exam.local",
            "aud": "some-other-audience.exam.local",
            "sub": "user-abc-123",
            "email": "test-user@exam.local",
            "exp": now + 3600,
        }
        wrong_aud_tok = jwt.encode(wrong_aud_payload, test_priv_pem, algorithm="RS256")
        res = client.post("/verify", json={"token": wrong_aud_tok})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        parts = valid_tok.split(".")
        tampered_body = base64.urlsafe_b64encode(
            b'{"iss":"https://idp.exam.local","aud":"tds-e8pdjl8x.apps.exam.local","sub":"hacker","exp":9999999999}'
        ).decode().rstrip("=")
        tampered_tok = f"{parts[0]}.{tampered_body}.{parts[2]}"
        res = client.post("/verify", json={"token": tampered_tok})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        wrong_iss_payload = {
            "iss": "https://attacker.idp.local",
            "aud": "tds-e8pdjl8x.apps.exam.local",
            "sub": "user-abc-123",
            "exp": now + 3600,
        }
        wrong_iss_tok = jwt.encode(wrong_iss_payload, test_priv_pem, algorithm="RS256")
        res = client.post("/verify", json={"token": wrong_iss_tok})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        res = client.post("/verify", json={})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        res = client.post("/verify", content=b"not json", headers={"Content-Type": "application/json"})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        res = client.options("/verify", headers={"Origin": "https://exam.portal.local", "Access-Control-Request-Method": "POST"})
        assert res.status_code == 200
        assert res.headers.get("access-control-allow-origin") == "https://exam.portal.local"

    finally:
        main.IDP_PUBLIC_KEY = orig_key

    unauthorized_tok = jwt.encode(
        {"iss": "https://idp.exam.local", "aud": "tds-e8pdjl8x.apps.exam.local", "exp": int(time.time()) + 3600},
        test_priv_pem,
        algorithm="RS256"
    )
    res = client.post("/verify", json={"token": unauthorized_tok})
    assert res.status_code == 401
    assert res.json() == {"valid": False}
    print("Question 4 tests passed!")


def test_question_7_analytics():
    print("--- Running Question 7 (POST Analytics Endpoint) Tests ---")
    api_key = "ak_dardxo7jihv44pvmrpzvpde7"

    res = client.options("/analytics", headers={
        "Origin": "https://exam.study.iitm.ac.in",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-api-key,content-type",
    })
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "https://exam.study.iitm.ac.in"

    sample_events = {"events": [{"user": "alice", "amount": 42.5, "ts": 1700000000}]}
    res = client.post("/analytics", json=sample_events)
    assert res.status_code == 401

    res = client.post("/analytics", json=sample_events, headers={"X-API-Key": "wrong_key_123"})
    assert res.status_code == 401

    res = client.post("/analytics", json=sample_events, headers={"X-API-Key": api_key})
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == USER_EMAIL
    assert data["total_events"] == 1
    assert data["unique_users"] == 1
    assert data["revenue"] == 42.5
    assert data["top_user"] == "alice"

    events = [
        {"user": "alice", "amount": 50.0, "ts": 1700000001},
        {"user": "bob", "amount": -20.0, "ts": 1700000002},
        {"user": "carol", "amount": 100.5, "ts": 1700000003},
        {"user": "dave", "amount": 0.0, "ts": 1700000004},
        {"user": "eve", "amount": 10.25, "ts": 1700000005},
        {"user": "alice", "amount": 30.0, "ts": 1700000006},
        {"user": "bob", "amount": 200.0, "ts": 1700000007},
        {"user": "carol", "amount": -50.0, "ts": 1700000008},
        {"user": "dave", "amount": 15.0, "ts": 1700000009},
        {"user": "eve", "amount": -5.0, "ts": 1700000010},
    ]

    res = client.post("/analytics", json={"events": events}, headers={
        "X-API-Key": api_key,
        "Origin": "https://exam.study.iitm.ac.in",
    })
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "https://exam.study.iitm.ac.in"
    data = res.json()
    assert data["email"] == USER_EMAIL
    assert data["total_events"] == 10
    assert data["unique_users"] == 5
    assert abs(data["revenue"] - 405.75) < 1e-4
    assert data["top_user"] == "bob"

    for _ in range(5):
        probe_users = [f"user_{i}" for i in range(random.randint(4, 7))]
        n_events = random.randint(8, 17)
        batch = []
        user_pos = collections.defaultdict(float)
        expected_rev = 0.0
        for _ in range(n_events):
            u = random.choice(probe_users)
            amt = round(random.uniform(-50, 100), 2)
            batch.append({"user": u, "amount": amt, "ts": int(time.time())})
            if amt > 0:
                user_pos[u] += amt
                expected_rev += amt

        sorted_pos = sorted(user_pos.items(), key=lambda x: x[1], reverse=True)
        if len(sorted_pos) >= 2 and abs(sorted_pos[0][1] - sorted_pos[1][1]) < 0.01:
            batch.append({"user": sorted_pos[0][0], "amount": 10.0, "ts": int(time.time())})
            user_pos[sorted_pos[0][0]] += 10.0
            expected_rev += 10.0

        expected_top = max(user_pos.items(), key=lambda x: x[1])[0]

        res = client.post("/analytics", json={"events": batch}, headers={"X-API-Key": api_key})
        assert res.status_code == 200
        d = res.json()
        assert d["email"] == USER_EMAIL
        assert d["total_events"] == len(batch)
        assert d["unique_users"] == len(set(e["user"] for e in batch))
        assert abs(d["revenue"] - expected_rev) < 0.05
        assert d["top_user"] == expected_top

    print("Question 7 tests passed!")


if __name__ == "__main__":
    test_question_8_observability()
    test_question_3_stats()
    test_question_4_verify()
    test_question_7_analytics()
    print("\nALL TEST SUITES PASSED PERFECTLY!")
