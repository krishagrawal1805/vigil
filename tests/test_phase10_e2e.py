import urllib.request
import json
import ssl
import time
import http.cookiejar

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

print("=================================================================")
print("STRIX PHASE 10: END-TO-END VERIFICATION OF PRACTICE LAB JOURNEY")
print("=================================================================")

# 1. Fetch CSRF Token
csrf_req = urllib.request.Request('https://localhost/api/v1/auth/csrf')
with opener.open(csrf_req) as r:
    csrf_data = json.loads(r.read().decode('utf-8'))
    csrf_token = csrf_data.get('csrf_token')
    print(f"1. CSRF Token obtained: {csrf_token[:16]}...")

# 2. Login as pentester
login_payload = json.dumps({'username': 'operator_phase10', 'password': 'Password123!', 'org_id': 'org-phase10'}).encode('utf-8')
login_req = urllib.request.Request('https://localhost/api/v1/auth/login', data=login_payload, headers={
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrf_token
})
with opener.open(login_req) as r:
    login_data = json.loads(r.read().decode('utf-8'))
    print(f"2. Login successful! User: {login_data.get('user', {}).get('username')}, Org: {login_data.get('user', {}).get('org_id')}")

# Update CSRF token after login cookie update
csrf_token = get_csrf_token() or csrf_token
print(f"   Refreshed CSRF Token from cookie: {csrf_token[:16]}...")

# 3. Check Profile / Me
me_req = urllib.request.Request('https://localhost/api/v1/auth/me')
with opener.open(me_req) as r:
    me_data = json.loads(r.read().decode('utf-8'))
    print(f"3. Profile confirmed: {me_data.get('username')}, Role: {me_data.get('role')}")

# 4. Check Practice Lab Status
lab_req = urllib.request.Request('https://localhost/api/lab/list')
lab_grant_id = None
lab_target_url = 'http://platform-practice-lab:3000'
with opener.open(lab_req) as r:
    labs = json.loads(r.read().decode('utf-8'))
    print(f"4. Managed labs count: {len(labs)}")
    for l in labs:
        if l.get('status') == 'running':
            lab_grant_id = l.get('grant_id')
            lab_target_url = l.get('target_url') or lab_target_url
            print(f"   Active lab found: {l.get('lab_instance_id')}, Grant: {lab_grant_id}")
            print(f"   Browser URL: {l.get('browser_url')}")
            print(f"   Internal Agent Target: {l.get('target_url')}")

# If not running, start one
if not lab_grant_id:
    start_payload = json.dumps({'duration_minutes': 60}).encode('utf-8')
    start_req = urllib.request.Request('https://localhost/api/lab/start', data=start_payload, headers={
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf_token
    })
    with opener.open(start_req) as r:
        start_res = json.loads(r.read().decode('utf-8'))
        lab_grant_id = start_res.get('lab_session', {}).get('grant_id')
        print(f"   Started practice lab with grant: {lab_grant_id}")

# 5. Launch Autonomous Pentest Run
start_run_payload = json.dumps({'grant_id': lab_grant_id, 'target_url': lab_target_url}).encode('utf-8')
start_run_req = urllib.request.Request('https://localhost/api/assessment/run', data=start_run_payload, headers={
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrf_token
})
with opener.open(start_run_req) as r:
    run_res = json.loads(r.read().decode('utf-8'))
    run_id = run_res.get('run_id')
    print(f"5. Assessment run started! Run ID: {run_id}")

# 6. Poll Live Status until completed
print("6. Polling live status (5-Phase tracking)...")
for i in range(40):
    status_req = urllib.request.Request('https://localhost/api/assessment/status')
    with opener.open(status_req) as r:
        st = json.loads(r.read().decode('utf-8'))
        curr_status = st.get('status')
        tools_c = st.get('tools_count', 0)
        find_c = st.get('findings_count', 0)
        print(f"   Poll {i+1}: status={curr_status}, tools={tools_c}, findings={find_c}")
        if curr_status in ['completed', 'failed', 'stopped']:
            break
    time.sleep(1)

# 7. Retrieve Final Results
results_req = urllib.request.Request(f'https://localhost/api/assessment/results?run_id={run_id}')
with opener.open(results_req) as r:
    results_data = json.loads(r.read().decode('utf-8'))
    print("\n7. Final Assessment Results Summary:")
    print(f"   Run ID: {results_data.get('run_id')}")
    print(f"   Status: {results_data.get('status')}")
    print(f"   Target: {results_data.get('target')}")
    print(f"   Duration: {results_data.get('duration_seconds')}s")
    print(f"   Tools executed: {len(results_data.get('tools_executed', []))}")
    for t in results_data.get('tools_executed', []):
        print(f"     - {t.get('tool')}: {t.get('invocations')} invocation(s) ({t.get('status')})")
    print(f"   Confirmed findings: {len(results_data.get('findings', []))}")
    for f in results_data.get('findings', []):
        print(f"     - [{f.get('severity')}] {f.get('title')}: {f.get('affected_url')} (confidence={f.get('confidence')})")
    print(f"   Executive report synthesized: {len(results_data.get('final_report', ''))} bytes")
    assert len(results_data.get('findings', [])) > 0, 'Should have verified findings'

print("\nSUCCESS: Complete STRIX Phase 10 User Journey Verified End-to-End!")
