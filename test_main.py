import time
import base64
import random
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


if __name__ == "__main__":
    test_question_3_stats()
    test_question_4_verify()
    print("\nALL TEST SUITES PASSED PERFECTLY!")
