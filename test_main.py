from starlette.testclient import TestClient
from main import app, ALLOWED_ORIGIN, USER_EMAIL

client = TestClient(app)

def test_preflight_allowed_origin():
    response = client.options(
        "/stats",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    assert "x-request-id" in response.headers
    assert "x-process-time" in response.headers
    process_time = float(response.headers["x-process-time"])
    assert process_time >= 0.0

def test_preflight_evil_origin():
    response = client.options(
        "/stats",
        headers={
            "Origin": "https://evil-attacker.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers
    assert "x-request-id" in response.headers
    assert "x-process-time" in response.headers

def test_get_stats_allowed_origin():
    response = client.get(
        "/stats?values=10,20,30,40",
        headers={"Origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    assert "x-request-id" in response.headers
    assert "x-process-time" in response.headers

    data = response.json()
    assert data["email"] == USER_EMAIL
    assert data["count"] == 4
    assert data["sum"] == 100
    assert data["min"] == 10
    assert data["max"] == 40
    assert abs(data["mean"] - 25.0) < 0.01

def test_get_stats_random_batch():
    import random
    batch = [random.randint(-1000, 1000) for _ in range(50)]
    val_str = ",".join(map(str, batch))

    response = client.get(f"/stats?values={val_str}")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    assert "x-process-time" in response.headers
    assert "access-control-allow-origin" not in response.headers

    data = response.json()
    assert data["email"] == USER_EMAIL
    assert data["count"] == len(batch)
    assert data["sum"] == sum(batch)
    assert data["min"] == min(batch)
    assert data["max"] == max(batch)
    assert abs(data["mean"] - (sum(batch) / len(batch))) < 0.01

if __name__ == "__main__":
    test_preflight_allowed_origin()
    test_preflight_evil_origin()
    test_get_stats_allowed_origin()
    test_get_stats_random_batch()
    print("ALL TESTS PASSED SUCCESSFULLY!")
