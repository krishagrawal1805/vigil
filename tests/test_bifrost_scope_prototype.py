import asyncio
import json
import logging
import ipaddress
import urllib.parse
from aiohttp import web
import httpx

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prototype")

# ---------------------------------------------------------
# 1. MOCK SECURITY MCP SERVER (Port 9090)
# ---------------------------------------------------------
mock_execution_count = 0

async def mock_security_server_handler(request: web.Request) -> web.Response:
    global mock_execution_count
    payload = await request.json()
    logger.info("[Mock-Security-Server] Received RPC: method=%s params=%s", payload.get("method"), payload.get("params"))
    
    if payload.get("method") == "tools/call":
        tool_name = payload.get("params", {}).get("name")
        args = payload.get("params", {}).get("arguments", {})
        
        if tool_name == "mock_scan":
            mock_execution_count += 1
            logger.info("[Mock-Security-Server] Executing mock_scan on target=%s (execution_count=%d)", args.get("target"), mock_execution_count)
            return web.json_response({
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "content": [{"type": "text", "text": f"Mock scan successful on target {args.get('target')}. Zero vulnerabilities detected."}],
                    "isError": False
                }
            })
    
    return web.json_response({
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "error": {"code": -32601, "message": "Method not found"}
    }, status=404)

async def start_mock_security_server():
    app = web.Application()
    app.router.add_post("/mcp", mock_security_server_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 9090)
    await site.start()
    logger.info("[Mock-Security-Server] Listening on http://127.0.0.1:9090/mcp")
    return runner

# ---------------------------------------------------------
# 2. BIFROST GATEWAY & SCOPE ENFORCER PLUGIN (Port 8080)
# ---------------------------------------------------------
class ScopeEnforcerPlugin:
    def __init__(self, allowed_cidrs: list[str], allowed_ports: list[int]):
        assert allowed_cidrs, "allowed_cidrs is mandatory"
        assert allowed_ports, "allowed_ports is mandatory"
        self.allowed_networks = [ipaddress.ip_network(c) for c in allowed_cidrs]
        self.allowed_ports = set(allowed_ports)
        self.authorized_tools = {
            "mock_scan": {"target_fields": ["target", "url"], "port_fields": ["port"]}
        }
    
    def pre_mcp_hook(self, tool_name: str, args: dict) -> tuple[bool, str | None]:
        logger.info("[ScopeEnforcerPlugin] PreMCPHook intercepted: tool=%s args=%s", tool_name, args)
        
        # Rule 4: Reject unknown security tools
        if tool_name not in self.authorized_tools:
            return False, f"tool '{tool_name}' is not in authorized security catalog"
        
        schema = self.authorized_tools[tool_name]
        
        # Rule 5: Reject missing or unrecognized target fields
        target_val = None
        for field in schema["target_fields"]:
            if field in args:
                target_val = str(args[field])
                break
        
        if not target_val:
            return False, f"tool '{tool_name}' requires a validated target field ({schema['target_fields']}), but none was provided"
        
        # Rule 9: Restrict protocols (HTTP/HTTPS only)
        if "://" in target_val:
            parsed = urllib.parse.urlparse(target_val)
            if parsed.scheme.lower() not in ("http", "https"):
                return False, f"unauthorized protocol scheme '{parsed.scheme}'; only http and https allowed"
            host = parsed.hostname
            port = parsed.port or (80 if parsed.scheme.lower() == "http" else 443)
        elif ":" in target_val:
            host, port_str = target_val.split(":", 1)
            port = int(port_str)
        else:
            host = target_val
            port = list(self.allowed_ports)[0] if len(self.allowed_ports) == 1 else None
            if port is None:
                return False, f"target '{target_val}' omitted port"

        # Rule 8: Enforce port restriction
        if port not in self.allowed_ports:
            return False, f"port {port} is not in allowed ports list ({list(self.allowed_ports)})"
        
        # Rule 8: Enforce IP / CIDR restriction
        try:
            ip_addr = ipaddress.ip_address(host)
        except ValueError:
            return False, f"unresolvable host '{host}'"
        
        in_scope = any(ip_addr in net for net in self.allowed_networks)
        if not in_scope:
            return False, f"IP {ip_addr} is outside allowed CIDR ranges ({[str(n) for n in self.allowed_networks]})"
        
        logger.info("[ScopeEnforcerPlugin] Target validation passed: IP=%s port=%d", ip_addr, port)
        return True, None

scope_enforcer = ScopeEnforcerPlugin(
    allowed_cidrs=["172.28.0.100/32"],
    allowed_ports=[3000]
)

async def bifrost_mcp_handler(request: web.Request) -> web.Response:
    payload = await request.json()
    logger.info("[Bifrost-Gateway] Ingress POST /mcp id=%s method=%s", payload.get("id"), payload.get("method"))
    
    if payload.get("method") == "tools/call":
        params = payload.get("params", {})
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        
        # Execute Plugin PreMCPHook
        allowed, denial_reason = scope_enforcer.pre_mcp_hook(tool_name, args)
        if not allowed:
            logger.warning("[Bifrost-Gateway] Short-circuiting execution: %s", denial_reason)
            return web.json_response({
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "content": [{"type": "text", "text": f"ScopeEnforcer: access denied - {denial_reason}"}],
                    "isError": True
                }
            })
        
        # If permitted, forward to backend Security MCP Server
        async with httpx.AsyncClient() as client:
            backend_resp = await client.post("http://127.0.0.1:9090/mcp", json=payload, timeout=5.0)
            return web.json_response(backend_resp.json(), status=backend_resp.status_code)
    
    return web.json_response({"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32601, "message": "Method not supported"}}, status=400)

async def start_bifrost_gateway():
    app = web.Application()
    app.router.add_post("/mcp", bifrost_mcp_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8080)
    await site.start()
    logger.info("[Bifrost-Gateway] Listening on http://127.0.0.1:8080/mcp")
    return runner

# ---------------------------------------------------------
# 3. TEST CLIENT & VERIFICATION HARNESS
# ---------------------------------------------------------
async def main():
    mock_runner = await start_mock_security_server()
    bifrost_runner = await start_bifrost_gateway()
    
    async with httpx.AsyncClient() as client:
        # TEST 1: Authorized Request
        logger.info("\n>>> RUNNING TEST 1: Authorized Target (172.28.0.100:3000)")
        req1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "mock_scan",
                "arguments": {"target": "http://172.28.0.100:3000/api/v1"}
            }
        }
        res1 = await client.post("http://127.0.0.1:8080/mcp", json=req1)
        data1 = res1.json()
        logger.info("Test 1 Response: %s", json.dumps(data1, indent=2))
        assert not data1["result"]["isError"], "Test 1 failed: Expected success"
        assert mock_execution_count == 1, f"Test 1 failed: Expected execution_count 1, got {mock_execution_count}"
        logger.info("TEST 1 PASSED: Authorized request successfully executed on mock backend (count=1).")
        
        # TEST 2: Unauthorized Request
        logger.info("\n>>> RUNNING TEST 2: Unauthorized Target (192.0.2.10:3000)")
        req2 = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "mock_scan",
                "arguments": {"target": "http://192.0.2.10:3000/api/v1"}
            }
        }
        res2 = await client.post("http://127.0.0.1:8080/mcp", json=req2)
        data2 = res2.json()
        logger.info("Test 2 Response: %s", json.dumps(data2, indent=2))
        assert data2["result"]["isError"], "Test 2 failed: Expected isError=True"
        assert "ScopeEnforcer: access denied" in data2["result"]["content"][0]["text"], "Test 2 failed: Expected denial message"
        assert mock_execution_count == 1, f"Test 2 failed: Expected execution_count to stay 1, got {mock_execution_count}"
        logger.info("TEST 2 PASSED: Unauthorized request was blocked before reaching mock backend (count remained 1).")

    await mock_runner.cleanup()
    await bifrost_runner.cleanup()
    logger.info("\nALL INTEGRATION PROTOTYPE TESTS PASSED.")

if __name__ == "__main__":
    asyncio.run(main())

