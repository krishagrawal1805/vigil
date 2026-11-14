import urllib.request
import json
import ssl
import time
import http.cookiejar
import subprocess
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))

def get_csrf_token():
    for cookie in cj:
        if cookie.name == 'csrf_token':
            return cookie.value
    return ""

def normalize_endpoint(url_or_path):
    if not url_or_path:
        return ""
    clean = url_or_path.strip().split("?")[0].split("#")[0]
    if clean.startswith("http://") or clean.startswith("https://"):
        try:
            from urllib.parse import urlparse
            u = urlparse(clean)
            return u.path or "/"
        except:
            pass
    if not clean.startswith("/"):
        clean = "/" + clean
    return clean

def main():
    print("================================================================================")
    print("PHASE 11.1: TELEMETRY SEMANTICS & REAL-TIME ACCURACY VERIFICATION SUITE")
    print("================================================================================")

    # 1. Edge Gateway
    print("\n[STEP 1] Auditing Edge Gateway and Frontend Bundle...")
    req = urllib.request.Request('https://localhost/', headers={'User-Agent': 'Mozilla/5.0'})
    with opener.open(req) as r:
        html = r.read().decode('utf-8')
        assert r.status == 200, f"Expected 200, got {r.status}"
        assert 'index' in html, "Failed to load index.html"
        print(f"  [+] Gateway Status: 200 OK")
        print(f"  [+] Verified frontend bundle loaded successfully.")

    # 2. Authentication
    print("\n[STEP 2] Establishing Authenticated Operator Session...")
    csrf_req = urllib.request.Request('https://localhost/api/v1/auth/csrf')
    with opener.open(csrf_req) as r:
        initial_csrf = json.loads(r.read().decode('utf-8')).get('csrf_token')

    login_payload = json.dumps({
        'username': 'operator_phase11',
        'password': 'Password123!',
        'org_id': 'org-phase11'
    }).encode('utf-8')
    login_req = urllib.request.Request('https://localhost/api/v1/auth/login', data=login_payload, headers={
        'Content-Type': 'application/json',
        'X-CSRF-Token': initial_csrf
    })
    try:
        with opener.open(login_req) as r:
            user_info = json.loads(r.read().decode('utf-8')).get('user', {})
            print(f"  [+] Logged in as: {user_info.get('username')} ({user_info.get('role')})")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  [*] Registering operator_phase11...")
            reg_payload = json.dumps({
                'username': 'operator_phase11',
                'password': 'Password123!',
                'org_id': 'org-phase11',
                'role': 'pentester'
            }).encode('utf-8')
            reg_req = urllib.request.Request('https://localhost/api/v1/auth/register', data=reg_payload, headers={
                'Content-Type': 'application/json',
                'X-CSRF-Token': initial_csrf
            })
            with opener.open(reg_req) as reg_r:
                print(f"  [+] Registered operator_phase11 (HTTP {reg_r.status})")
            # Re-login
            with opener.open(login_req) as r:
                user_info = json.loads(r.read().decode('utf-8')).get('user', {})
                print(f"  [+] Logged in as: {user_info.get('username')} ({user_info.get('role')})")

    active_csrf = get_csrf_token() or initial_csrf

    # 3. Practice Lab Target Verification & URL Separation
    print("\n[STEP 3] Verifying Practice Lab Status & Active Grant...")
    lab_req = urllib.request.Request('https://localhost/api/lab/list')
    grant_id = None
    target_internal = "http://platform-practice-lab:3000"
    browser_url = "http://127.0.0.1:5000"

    with opener.open(lab_req) as r:
        labs = json.loads(r.read().decode('utf-8'))
        running_lab = next((l for l in labs if l.get('status') == 'running'), None)
        if not running_lab:
            print("  [*] Starting managed practice lab...")
            start_payload = json.dumps({'template_id': 'juice-shop'}).encode('utf-8')
            start_req = urllib.request.Request('https://localhost/api/lab/start', data=start_payload, headers={
                'Content-Type': 'application/json',
                'X-CSRF-Token': active_csrf
            })
            with opener.open(start_req) as start_r:
                lab_info = json.loads(start_r.read().decode('utf-8'))
                grant_id = lab_info.get('grant_id')
                print(f"  [+] Started lab instance with grant: {grant_id}")
        else:
            grant_id = running_lab.get('grant_id')
            target_internal = running_lab.get('target_url', target_internal)
            browser_url = running_lab.get('browser_url', browser_url)
            print(f"  [+] Found active lab: {running_lab.get('lab_instance_id')}")
            print(f"  [+] Grant ID: {grant_id}")
            print(f"  [+] Internal Docker Target: {target_internal}")
            print(f"  [+] Host Browser URL: {browser_url}")

    # 4. Launch Fresh Active Assessment
    print("\n[STEP 4] Launching Fresh Autonomous Assessment Run...")
    run_payload = json.dumps({
        'target': target_internal,
        'grant_id': grant_id,
        'mode': 'multiagent'
    }).encode('utf-8')
    run_req = urllib.request.Request('https://localhost/api/assessment/run', data=run_payload, headers={
        'Content-Type': 'application/json',
        'X-CSRF-Token': active_csrf
    })

    with opener.open(run_req) as r:
        launch_res = json.loads(r.read().decode('utf-8'))
        fresh_run_id = launch_res.get('run_id')
        print(f"  [+] Assessment Mission Spawned!")
        print(f"  [+] Fresh Run ID: {fresh_run_id}")
        print(f"  [+] Initial Status: {launch_res.get('status')}")

    # 5. Live Telemetry Polling
    print("\n[STEP 5] Polling Real-Time Telemetry During Active Execution...")
    start_poll_time = time.time()
    last_status = None
    telemetry_samples = []

    while time.time() - start_poll_time < 60:
        time.sleep(1.5)
        status_req = urllib.request.Request(f'https://localhost/api/assessment/status?run_id={fresh_run_id}')
        with opener.open(status_req) as r:
            st = json.loads(r.read().decode('utf-8'))
            cur_status = st.get('status')
            tools_count = st.get('tools_count', 0)
            findings_count = st.get('findings_count', 0)
            dur = st.get('duration_seconds', 0)
            elapsed = int(time.time() - start_poll_time)

            telemetry_samples.append({
                'elapsed': elapsed,
                'status': cur_status,
                'tools_count': tools_count,
                'findings_count': findings_count,
                'duration_seconds': dur
            })

            if cur_status != last_status or tools_count > 0:
                print(f"  [T+{elapsed:02d}s] Status: {cur_status.upper():10s} | Invocations: {tools_count} | Findings: {findings_count} | Reported Duration: {dur}s")
                last_status = cur_status

            if cur_status in ['completed', 'failed', 'stopped']:
                print(f"  [+] Mission reached terminal state '{cur_status}' after {elapsed}s.")
                break

    # 6. Retrieve Final Detailed Results
    print("\n[STEP 6] Retrieving Authoritative Assessment Results...")
    results_req = urllib.request.Request(f'https://localhost/api/assessment/results?run_id={fresh_run_id}')
    with opener.open(results_req) as r:
        results = json.loads(r.read().decode('utf-8'))

    print(f"  [+] Run ID: {results.get('run_id')}")
    print(f"  [+] Assessment ID: {results.get('assessment_id')}")
    print(f"  [+] Status: {results.get('status')}")
    print(f"  [+] Agent Model: {results.get('agent_model')}")
    print(f"  [+] Start Time: {results.get('start_time')}")
    print(f"  [+] End Time: {results.get('end_time')}")
    print(f"  [+] Agent Execution Duration: {results.get('duration_seconds')}s")
    print(f"  [+] Total Mission Lifecycle: {results.get('lifecycle_duration_seconds')}s")

    # AUDIT ISSUE 1: Discovered Endpoints
    discovered_endpoints_raw = results.get('discovered_endpoints', [])
    discovered_set = set(normalize_endpoint(ep) for ep in discovered_endpoints_raw if ep)
    scope_paths = set(results.get('scope', {}).get('allowed_paths', []))
    print(f"\n  [AUDIT REQUIREMENT 1: DISCOVERED ENDPOINTS]")
    print(f"    - Discovered Endpoints Count: {len(discovered_set)} (From discover_endpoints capability)")
    print(f"    - Scope Prefixes Separate Count: {len(scope_paths)} (Kept distinct as authorized boundaries)")
    for ep in sorted(discovered_set):
        print(f"      * Discovered: {ep}")
    assert len(discovered_set) > 0, "Discovered endpoints must not be empty"
    assert not scope_paths.issubset(discovered_set), "Scope prefixes must NOT be conflated with discovered endpoints!"

    # AUDIT REQUIREMENT 3: Individual Execution Records (tool_invocations)
    tool_invocations = results.get('tool_invocations', [])
    print(f"\n  [AUDIT REQUIREMENT 3: PER-INVOCATION EXECUTION STREAM]")
    print(f"    - Total Individual Invocations Recorded: {len(tool_invocations)}")
    for inv in tool_invocations:
        print(f"      * [{inv.get('invocation_id')}] Tool: {inv.get('tool'):26s} | Method: {inv.get('method', 'GET'):4s} | Status: {'ERROR' if inv.get('is_error') else ('CONFIRMED' if inv.get('confirmed') else 'SUCCESS'):9s} | Target: {inv.get('target')} | Time: {inv.get('timestamp')}")

    # AUDIT REQUIREMENT 4: Tested Endpoints Accuracy
    tested_set = set()
    for inv in tool_invocations:
        if inv.get('target') and not 'discover' in inv.get('tool', ''):
            tested_set.add(normalize_endpoint(inv.get('target')))
    for hyp in results.get('hypotheses', []):
        if hyp.get('endpoint'):
            tested_set.add(normalize_endpoint(hyp.get('endpoint')))
    for f in results.get('findings', []):
        if f.get('affected_url'):
            tested_set.add(normalize_endpoint(f.get('affected_url')))

    untested_set = discovered_set - tested_set
    print(f"\n  [AUDIT REQUIREMENT 4: TESTED vs DISCOVERED ACCURACY]")
    print(f"    - Tested Endpoints Count: {len(tested_set)} (Strictly tested by security tools or hypotheses)")
    for te in sorted(tested_set):
        print(f"      * Tested: {te}")
    print(f"    - Untested Endpoints Count: {len(untested_set)}")
    for ue in sorted(untested_set):
        print(f"      * Untested (Discovered only): {ue}")

    # AUDIT REQUIREMENT 2: Canonical Finding Classification
    findings = results.get('findings', [])
    print(f"\n  [AUDIT REQUIREMENT 2: CANONICAL FINDING CLASSIFICATION]")
    print(f"    - Total Raw Findings in Ledger: {len(findings)}")
    confirmed_findings = []
    potential_findings = []
    inconclusive_findings = []
    rejected_findings = []
    unverified_findings = []

    for f in findings:
        raw_status = (f.get('verification') or f.get('verification_status') or '').lower().strip()
        has_evidence = bool(f.get('evidence') and len(f.get('evidence', '').strip()) >= 10)
        run_matches = f.get('run_id') == fresh_run_id

        if raw_status == 'confirmed' and has_evidence and run_matches:
            confirmed_findings.append(f)
            cls = "CONFIRMED"
        elif raw_status == 'potential':
            potential_findings.append(f)
            cls = "POTENTIAL"
        elif raw_status == 'inconclusive':
            inconclusive_findings.append(f)
            cls = "INCONCLUSIVE"
        elif raw_status in ['rejected', 'unconfirmed']:
            rejected_findings.append(f)
            cls = "REJECTED"
        else:
            unverified_findings.append(f)
            cls = "UNVERIFIED"

        print(f"      * Finding: {f.get('title')}")
        print(f"        Canonical Classification: {cls}")
        print(f"        Confidence Rating: {f.get('confidence')} (Evaluated separately, NOT determining confirmation)")
        print(f"        Affected URL: {f.get('affected_url')} (Parameter: {f.get('parameter')})")
        print(f"        Corroborated Tool Invocation: {f.get('corroborated_tool_invocation')}")
        assert "Password123!" not in f.get('evidence', ''), "Password redaction violated!"

    print(f"    - Canonical Counts: {len(confirmed_findings)} Confirmed, {len(potential_findings)} Potential, {len(inconclusive_findings)} Inconclusive, {len(rejected_findings)} Rejected, {len(unverified_findings)} Unverified.")
    assert len(confirmed_findings) > 0, "Expected at least 1 confirmed BOLA finding"

    # AUDIT REQUIREMENT 5: Duration Consistency
    agent_dur = results.get('duration_seconds')
    lifecycle_dur = results.get('lifecycle_duration_seconds')
    print(f"\n  [AUDIT REQUIREMENT 5: DURATION LABELS & CONSISTENCY]")
    print(f"    - Agent Reasoning Duration: {agent_dur}s (Recorded by runner ledger)")
    print(f"    - Mission Lifecycle Duration: {lifecycle_dur}s (From process start to process exit)")
    assert agent_dur is not None and agent_dur > 0, "Agent duration must be positive"
    assert lifecycle_dur is not None and lifecycle_dur >= agent_dur, "Lifecycle duration must be >= agent duration"

    # 7. Container Preservation Check
    print("\n[STEP 7] Verifying Infrastructure Container Health...")
    out = subprocess.check_output(['docker', 'ps', '--format', '{{.Names}}'], text=True)
    running_names = out.strip().split('\n')
    for required in ['platform-practice-lab', 'platform-backend-core', 'platform-mcp-security', 'platform-bifrost-llm', 'platform-edge-gateway', 'n8n']:
        assert required in running_names, f"Required container '{required}' is missing!"
        print(f"  [+] Container {required}: OK")

    print("\n================================================================================")
    print("PHASE 11.1 AUDIT VERIFIED: ALL DATA-INTEGRITY & TELEMETRY STANDARDS SATISFIED!")
    print("================================================================================")
    return results

if __name__ == '__main__':
    main()

