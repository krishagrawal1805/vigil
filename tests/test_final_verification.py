import urllib.request
import ssl
import json
import time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE_URL = "https://127.0.0.1"

def test_health():
    print("[1] Testing platform health...")
    req = urllib.request.Request(f"{BASE_URL}/api/health")
    with urllib.request.urlopen(req, context=ctx) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        print("    Platform health:", data)
        assert data["platform"] == "healthy"
        assert data["service"] == "autonomous-penetration-testing-platform"
    print("    PASSED!")

def test_frontend_assets():
    print("[2] Verifying frontend bundle for AEGIS rebranding...")
    req = urllib.request.Request(f"{BASE_URL}/")
    with urllib.request.urlopen(req, context=ctx) as resp:
        html = resp.read().decode()
        assert resp.status == 200
        print("    HTML loaded (length:", len(html), ")")
        assert "strix" not in html.lower(), "strix found in index.html"
        assert "pentagi" not in html.lower(), "pentagi found in index.html"
    print("    PASSED!")

def test_practice_lab_and_assessment():
    print("[3] Testing 1-click practice assessment lifecycle...")
    # Register/login user with unique username
    uname = f"vigil_user_{int(time.time())}"
    pwd = "PentestPassword2026!"
    reg_data = json.dumps({"username": uname, "password": pwd, "role": "pentester"}).encode()
    reg_req = urllib.request.Request(f"{BASE_URL}/api/v1/auth/register", data=reg_data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(reg_req, context=ctx) as resp:
        assert resp.status == 201

    login_req = urllib.request.Request(f"{BASE_URL}/api/v1/auth/login", data=reg_data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(login_req, context=ctx) as resp:
        cookie = resp.headers.get("Set-Cookie")
        assert cookie is not None
        print(f"    Logged in successfully as {uname}. Session cookie acquired.")

    headers = {"Cookie": cookie, "Content-Type": "application/json"}

    # Start lab
    lab_req = urllib.request.Request(f"{BASE_URL}/api/lab/start", data=json.dumps({"duration_minutes": 60}).encode(), headers=headers)
    with urllib.request.urlopen(lab_req, context=ctx) as resp:
        lab_data = json.loads(resp.read().decode())
        grant_id = lab_data.get("grant_id")
        lab_session = lab_data.get("lab_session")
        print(f"    Lab running. Container: {lab_session.get('container_id')}, Grant ID: {grant_id}")
        assert "platform-practice-lab" in lab_session.get("container_id", "") or "juice-shop" in lab_session.get("container_id", "")

    # Start assessment run
    run_req = urllib.request.Request(f"{BASE_URL}/api/assessment/run", data=json.dumps({"grant_id": grant_id}).encode(), headers=headers)
    with urllib.request.urlopen(run_req, context=ctx) as resp:
        run_data = json.loads(resp.read().decode())
        run_id = run_data.get("run_id")
        print(f"    Assessment run launched: {run_id}")
        assert run_id is not None

    # Wait for completion (up to 45s)
    print("    Polling assessment status...")
    for _ in range(30):
        time.sleep(1.5)
        status_req = urllib.request.Request(f"{BASE_URL}/api/assessment/status", headers=headers)
        with urllib.request.urlopen(status_req, context=ctx) as resp:
            status_data = json.loads(resp.read().decode())
            st = status_data.get("status")
            if st in ["completed", "failed"]:
                print(f"    Assessment concluded with status: {st}")
                break

    # Fetch results
    results_req = urllib.request.Request(f"{BASE_URL}/api/assessment/results?run_id={run_id}", headers=headers)
    with urllib.request.urlopen(results_req, context=ctx) as resp:
        results = json.loads(resp.read().decode())
        print(f"    Results for {run_id}:")
        print(f"    - Findings: {len(results.get('findings', []))}")
        print(f"    - Discovered Endpoints: {len(results.get('discovered_endpoints', []))}")
        print(f"    - Invocations: {len(results.get('tool_invocations', []))}")
        assert len(results.get("findings", [])) > 0
        finding = results["findings"][0]
        print(f"    - Canonical Finding: {finding.get('id')} - {finding.get('title')}")
        print(f"    - CWE: {finding.get('cwe')}, Corroboration: {finding.get('corroborated_tool_invocation')}")
    print("    PASSED!")

if __name__ == "__main__":
    test_health()
    test_frontend_assets()
    test_practice_lab_and_assessment()
    print("\nALL SYSTEM VERIFICATION TESTS PASSED SUCCESSFULLY!")
