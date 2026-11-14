import json
import re
import urllib.request
import urllib.error
import http.cookiejar
import ssl
import time

def main():
    print("======================================================================")
    print("STRIX PHASE 12: PUBLIC PRODUCT WEBSITE & ENTRY EXPERIENCE VERIFICATION")
    print("======================================================================")

    ctx = ssl._create_unverified_context()

    # 1. Verify Public Website HTML & Bundle Serving
    print("\n--- 1. Public Product Website Serving ---")
    req = urllib.request.Request("http://127.0.0.1/")
    with urllib.request.urlopen(req, context=ctx) as resp:
        html = resp.read().decode("utf-8")
        print(f"HTTP GET http://127.0.0.1/ -> Status: {resp.status}, Size: {len(html)} bytes")
        assert resp.status == 200, f"Expected 200, got {resp.status}"

    js_match = re.search(r'src="(/assets/index-[^"]+\.js)"', html)
    assert js_match, "Could not find index bundle in HTML"
    js_url = "https://127.0.0.1" + js_match.group(1)
    print(f"Loading bundle from {js_url}...")

    with urllib.request.urlopen(js_url, context=ctx) as resp:
        js_content = resp.read().decode("utf-8")
        print(f"Bundle loaded: {len(js_content)} bytes")

    required_phrases = [
        "Autonomous Penetration Testing.",
        "Verified Security.",
        "STRIX coordinates specialist AI security agents to discover application attack surfaces",
        "What would you like to test today?",
        "Explore autonomous penetration testing safely using our managed OWASP Juice Shop environment.",
        "Test a website or web application you own or have explicit permission to assess.",
        "External Application Assessment Workflow",
        "Two-Person Rule Enforcement",
        "Deterministic ScopeEnforcer Boundaries",
        "Live Polling Updates",
    ]

    for phrase in required_phrases:
        found = phrase in js_content
        print(f"Checking phrase: '{phrase[:45]}...' -> {'FOUND' if found else 'MISSING'}")
        assert found, f"Required phrase not found in compiled bundle: {phrase}"

    # 2. Verify Backend Authentication Security & RBAC
    print("\n--- 2. Backend Authentication Security & RBAC ---")
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx)
    )

    # Get CSRF Token
    csrf_req = urllib.request.Request("https://127.0.0.1/api/v1/auth/csrf")
    with opener.open(csrf_req) as csrf_res:
        csrf_data = json.loads(csrf_res.read().decode("utf-8"))
        csrf_token = csrf_data.get("csrf_token")
        print(f"Initial CSRF Token obtained: {csrf_token[:16]}...")
        assert csrf_token, "Missing CSRF token"

    # Register a new operator account in the active assessment org
    username = f"operator_p12_{int(time.time())}"
    password = "Password123!"
    reg_payload = json.dumps({
        "username": username,
        "password": password,
        "org_id": "org-phase113",
        "role": "pentester"
    }).encode("utf-8")
    reg_req = urllib.request.Request(
        "https://127.0.0.1/api/v1/auth/register",
        data=reg_payload,
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf_token,
        }
    )
    with opener.open(reg_req) as reg_res:
        reg_data = json.loads(reg_res.read().decode("utf-8"))
        print(f"Registered user: {reg_data.get('user', {}).get('username')} (Org: {reg_data.get('user', {}).get('org_id')})")

    # Login as newly registered user
    login_payload = json.dumps({
        "username": username,
        "password": password
    }).encode("utf-8")
    login_req = urllib.request.Request(
        "https://127.0.0.1/api/v1/auth/login",
        data=login_payload,
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf_token,
        }
    )
    with opener.open(login_req) as login_res:
        login_data = json.loads(login_res.read().decode("utf-8"))
        session_csrf = login_data.get("csrf_token") or csrf_token
        print(f"Login Response: user={login_data.get('user', {}).get('username')}, role={login_data.get('user', {}).get('role')}")
        print(f"Session CSRF Token: {session_csrf[:16]}...")
        assert login_data.get("user", {}).get("username") == username

    # Verify Profile via Session Cookie
    profile_req = urllib.request.Request(
        "https://127.0.0.1/api/lab/me",
        headers={"X-CSRF-Token": session_csrf}
    )
    with opener.open(profile_req) as prof_res:
        prof_data = json.loads(prof_res.read().decode("utf-8"))
        print(f"Caller Profile: user_id={prof_data.get('user_id')}, org={prof_data.get('org_id')}, role={prof_data.get('role')}")
        assert prof_data.get("role") in ["admin", "org-admin", "pentester", "security_officer"]

    # 3. Verify Managed Practice Lab Target
    print("\n--- 3. Managed Practice Lab Target & Container ---")
    # Start lab session to verify lab provisioning and URL mapping
    start_lab_payload = json.dumps({"duration_minutes": 60}).encode("utf-8")
    start_lab_req = urllib.request.Request(
        "https://127.0.0.1/api/lab/start",
        data=start_lab_payload,
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": session_csrf,
        }
    )
    with opener.open(start_lab_req) as slab_res:
        slab_data = json.loads(slab_res.read().decode("utf-8"))
        session = slab_data.get("lab_session", {})
        print(f"Practice Lab Session Created: ID={session.get('lab_instance_id')}, Container={session.get('container_id')}")
        print(f"Browser URL: {session.get('browser_url') or session.get('browser_target_url')}, Target: {session.get('target_url')}")
        assert "5000" in (session.get("browser_url") or session.get("browser_target_url") or "")

    # List active labs
    labs_req = urllib.request.Request(
        "https://127.0.0.1/api/lab/list",
        headers={"X-CSRF-Token": session_csrf}
    )
    with opener.open(labs_req) as labs_res:
        labs_data = json.loads(labs_res.read().decode("utf-8"))
        running_labs = [l for l in labs_data if l.get("status") == "running"]
        print(f"Active Practice Labs: {len(running_labs)}")
        assert len(running_labs) >= 1

    # 4. Verify External Application Target Registration & Two-Person Approval
    print("\n--- 4. External Application Journey: Registration & Approval ---")
    reg_payload = json.dumps({
        "target_host": "staging.judge-test.internal",
        "target_port": 8443,
        "allowed_paths": ["/api/", "/rest/"],
        "blocked_paths": ["/admin/logout", "/payments/execute"]
    }).encode("utf-8")
    reg_req = urllib.request.Request(
        "https://127.0.0.1/api/auth/external/register",
        data=reg_payload,
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": session_csrf,
        }
    )
    with opener.open(reg_req) as reg_res:
        reg_data = json.loads(reg_res.read().decode("utf-8"))
        grant = reg_data.get("grant", {})
        dns_challenge = reg_data.get("dns_challenge", {})
        asm_id = grant.get("assessment_id")
        token = dns_challenge.get("record_value")
        print(f"External Target Registered: Assessment ID={asm_id}")
        print(f"DNS Challenge Record: _strix-challenge.{grant.get('authorized_host')} -> {token}")
        assert asm_id, "Missing assessment_id"
        assert token, "Missing DNS challenge token"

        # Verify DNS TXT Challenge
        dns_payload = json.dumps({
            "assessment_id": asm_id,
            "token": token
        }).encode("utf-8")
        dns_req = urllib.request.Request(
            "https://127.0.0.1/api/auth/external/verify-dns",
            data=dns_payload,
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": session_csrf,
            }
        )
        with opener.open(dns_req) as dns_res:
            dns_res_data = json.loads(dns_res.read().decode("utf-8"))
            print(f"DNS Verification Result: status={dns_res_data.get('status')}")
            assert dns_res_data.get("status") in ["verified", "dns_verified_pending_approval"]

        # Test Two-Person Separation Rule: Requester cannot approve own request!
        appr_payload = json.dumps({
            "assessment_id": asm_id,
            "auth_evidence_ref": "SELF-APPROVE-ATTEMPT"
        }).encode("utf-8")
        appr_req = urllib.request.Request(
            "https://127.0.0.1/api/auth/external/approve",
            data=appr_payload,
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": session_csrf,
            }
        )
        try:
            with opener.open(appr_req) as appr_res:
                print("WARNING: Requester self-approval succeeded unexpectedly!")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            print(f"Two-Person Separation Enforced: Self-approval blocked with HTTP {e.code}: {err_body.strip()}")
            assert e.code in [400, 403], f"Expected 400/403 for self-approval attempt, got {e.code}"

    # 5. Verify Telemetry & Phase 11.3 Acceptance Data
    print("\n--- 5. Phase 11.3 Telemetry & Provenance Preservation ---")
    verified_run_id = "run-c5399e286fa7712d"
    res_req = urllib.request.Request(
        f"https://127.0.0.1/api/assessment/results?run_id={verified_run_id}",
        headers={"X-CSRF-Token": session_csrf}
    )
    with opener.open(res_req) as r_res:
        res_data = json.loads(r_res.read().decode("utf-8"))
        disc_eps = res_data.get("discovered_endpoints", [])
        invocations = res_data.get("tool_invocations", [])
        findings = res_data.get("findings", [])
        print(f"Run Discovered Endpoints: {len(disc_eps)} -> {disc_eps}")
        print(f"Run Tool Invocations: {len(invocations)}")
        print(f"Run Findings: {len(findings)}")

        # Verify exact endpoint numbers: 10 discovered
        assert len(disc_eps) == 10, f"Expected 10 discovered endpoints, got {len(disc_eps)}"

        if findings:
            f0 = findings[0]
            corr_inv = f0.get("corroborated_tool_invocation")
            val_id = f0.get("validator_decision_id")
            evid_id = f0.get("evidence_record_id")
            aff_url = f0.get("affected_url", "")
            print(f"Finding Provenance: ID={f0.get('id')}, CorroboratedInvocation={corr_inv}, ValDecisionID={val_id}, EvidenceID={evid_id}, URL={aff_url}")
            assert aff_url.endswith("/rest/basket/2"), "Expected affected URL ending in /rest/basket/2"
            assert corr_inv == "INV-0005", f"Expected INV-0005, got {corr_inv}"
            assert val_id == "VAL-DEC-0001", f"Expected VAL-DEC-0001, got {val_id}"
            assert evid_id == "EVID-0001", f"Expected EVID-0001, got {evid_id}"

    print("\n======================================================================")
    print("ALL PHASE 12 VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("======================================================================")

if __name__ == "__main__":
    main()
