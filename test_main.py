import time
import base64
import random
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


def test_question_3_stats():
    print("--- Running Question 3 (Stats & CORS) Tests ---")
    # Preflight allowed origin
    res = client.options("/stats", headers={
        "Origin": ALLOWED_ORIGIN_STATS,
        "Access-Control-Request-Method": "GET",
    })
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN_STATS
    assert "x-request-id" in res.headers
    assert "x-process-time" in res.headers

    # Preflight evil origin
    res = client.options("/stats", headers={
        "Origin": "https://evil.attacker.com",
        "Access-Control-Request-Method": "GET",
    })
    assert "access-control-allow-origin" not in res.headers
    assert "x-request-id" in res.headers
    assert "x-process-time" in res.headers

    # GET /stats allowed origin
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

    # GET /stats without origin header
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
    # Temporarily patch IDP_PUBLIC_KEY with our test public key for testing
    orig_key = main.IDP_PUBLIC_KEY
    main.IDP_PUBLIC_KEY = test_pub_pem
    try:
        now = int(time.time())

        # Probe 1: A freshly minted valid token
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
        print("Probe 1 (Valid token): PASSED ->", data)

        # Probe 2: An expired token (exp in past)
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
        print("Probe 2 (Expired token): PASSED -> 401 rejected")

        # Probe 3: A token with the wrong audience
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
        print("Probe 3 (Wrong audience): PASSED -> 401 rejected")

        # Probe 4: A token with a tampered payload and invalid signature
        parts = valid_tok.split(".")
        tampered_body = base64.urlsafe_b64encode(
            b'{"iss":"https://idp.exam.local","aud":"tds-e8pdjl8x.apps.exam.local","sub":"hacker","exp":9999999999}'
        ).decode().rstrip("=")
        tampered_tok = f"{parts[0]}.{tampered_body}.{parts[2]}"
        res = client.post("/verify", json={"token": tampered_tok})
        assert res.status_code == 401
        assert res.json() == {"valid": False}
        print("Probe 4 (Tampered token): PASSED -> 401 rejected")

        # Extra: Wrong issuer
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
        print("Extra (Wrong issuer): PASSED -> 401 rejected")

        # Extra: Empty / malformed requests
        res = client.post("/verify", json={})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        res = client.post("/verify", content=b"not json", headers={"Content-Type": "application/json"})
        assert res.status_code == 401
        assert res.json() == {"valid": False}

        # Extra: Preflight on /verify
        res = client.options("/verify", headers={"Origin": "https://exam.portal.local", "Access-Control-Request-Method": "POST"})
        assert res.status_code == 200
        assert res.headers.get("access-control-allow-origin") == "https://exam.portal.local"
        print("Extra (Preflight on /verify): PASSED")

    finally:
        main.IDP_PUBLIC_KEY = orig_key

    # Also test actual configured IDP_PUBLIC_KEY rejection of an unauthorized signature
    # (signed with arbitrary key instead of configured real IDP key)
    unauthorized_tok = jwt.encode(
        {"iss": "https://idp.exam.local", "aud": "tds-e8pdjl8x.apps.exam.local", "exp": int(time.time()) + 3600},
        test_priv_pem,
        algorithm="RS256"
    )
    res = client.post("/verify", json={"token": unauthorized_tok})
    assert res.status_code == 401
    assert res.json() == {"valid": False}
    print("Real IDP public key verification against arbitrary key: PASSED -> 401 rejected")


def test_question_7_analytics():
    print("--- Running Question 7 (POST Analytics Endpoint) Tests ---")
    api_key = "ak_dardxo7jihv44pvmrpzvpde7"

    # Test 1: Preflight OPTIONS on /analytics
    res = client.options("/analytics", headers={
        "Origin": "https://exam.study.iitm.ac.in",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-api-key,content-type",
    })
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "https://exam.study.iitm.ac.in"
    print("Test 1 (CORS Preflight on /analytics): PASSED")

    # Test 2: Missing API key -> 401
    sample_events = {"events": [{"user": "alice", "amount": 42.5, "ts": 1700000000}]}
    res = client.post("/analytics", json=sample_events)
    assert res.status_code == 401
    print("Test 2 (Missing API key -> 401): PASSED")

    # Test 3: Wrong API key -> 401
    res = client.post("/analytics", json=sample_events, headers={"X-API-Key": "wrong_key_123"})
    assert res.status_code == 401
    print("Test 3 (Wrong API key -> 401): PASSED")

    # Test 4: Valid key with sample from problem description
    res = client.post("/analytics", json=sample_events, headers={"X-API-Key": api_key})
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == USER_EMAIL
    assert data["total_events"] == 1
    assert data["unique_users"] == 1
    assert data["revenue"] == 42.5
    assert data["top_user"] == "alice"
    print("Test 4 (Single event): PASSED ->", data)

    # Test 5: Randomized batch with 8-17 events, 4-7 users, mixed positive/negative amounts
    users = ["alice", "bob", "carol", "dave", "eve"]
    events = [
        {"user": "alice", "amount": 50.0, "ts": 1700000001},
        {"user": "bob", "amount": -20.0, "ts": 1700000002},
        {"user": "carol", "amount": 100.5, "ts": 1700000003},
        {"user": "dave", "amount": 0.0, "ts": 1700000004},
        {"user": "eve", "amount": 10.25, "ts": 1700000005},
        {"user": "alice", "amount": 30.0, "ts": 1700000006},
        {"user": "bob", "amount": 200.0, "ts": 1700000007},  # bob's positive is 200.0
        {"user": "carol", "amount": -50.0, "ts": 1700000008},
        {"user": "dave", "amount": 15.0, "ts": 1700000009},
        {"user": "eve", "amount": -5.0, "ts": 1700000010},
    ]
    # Total events: 10
    # Unique users: 5 (alice, bob, carol, dave, eve)
    # Positive amounts:
    # alice: 50.0 + 30.0 = 80.0
    # bob: 200.0 (the -20.0 is ignored)
    # carol: 100.5 (the -50.0 is ignored)
    # dave: 15.0 (0.0 ignored)
    # eve: 10.25 (-5.0 ignored)
    # Revenue: 80.0 + 200.0 + 100.5 + 15.0 + 10.25 = 405.75
    # Top user: bob (200.0)

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
    print("Test 5 (Mixed batch): PASSED ->", data)

    # Test 6: 15 randomized events generator to simulate grader Probe
    for probe_idx in range(5):
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

        # Ensure no tie by bumping one user slightly if needed
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
    print("Test 6 (Randomized probes simulation): PASSED")


if __name__ == "__main__":
    test_question_3_stats()
    test_question_4_verify()
    test_question_7_analytics()
    print("\nALL TEST SUITES PASSED PERFECTLY!")
