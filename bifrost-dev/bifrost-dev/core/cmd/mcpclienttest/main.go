package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

type UpstreamStats struct {
	RequestsReceived int64             `json:"requests_received"`
	History          []json.RawMessage `json:"history"`
}

func getUpstreamStats() (*UpstreamStats, error) {
	resp, err := http.Get("http://127.0.0.1:3011/stats")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var stats UpstreamStats
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: mcpclienttest <virtual_key>")
	}
	virtualKey := os.Args[1]

	bifrostMCPURL := "http://127.0.0.1:8080/mcp"
	fmt.Printf("[TEST SUITE] Connecting real MCP client to Bifrost endpoint: %s\n", bifrostMCPURL)
	fmt.Printf("[TEST SUITE] Using Virtual Key: %s\n", virtualKey)

	// Step 0: Check initial upstream stats
	initStats, err := getUpstreamStats()
	if err != nil {
		log.Fatalf("Failed to query mock server stats: %v", err)
	}
	fmt.Printf("[BASELINE] Upstream mock server requests received so far: %d\n", initStats.RequestsReceived)

	// Step 1: Create Streamable HTTP transport with authentication header
	headers := map[string]string{
		"x-bf-vk": virtualKey,
	}
	opts := []transport.StreamableHTTPCOption{
		transport.WithHTTPHeaders(headers),
	}
	httpTransport, err := transport.NewStreamableHTTP(bifrostMCPURL, opts...)
	if err != nil {
		log.Fatalf("Failed to create StreamableHTTP transport: %v", err)
	}

	mcpClient := client.NewClient(httpTransport)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := mcpClient.Start(ctx); err != nil {
		log.Fatalf("Failed to start MCP client: %v", err)
	}
	defer mcpClient.Close()

	// Step 2: Initialize
	initReq := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "strix-verification-client",
				Version: "1.0.0",
			},
			Capabilities: mcp.ClientCapabilities{},
		},
	}
	initResult, err := mcpClient.Initialize(ctx, initReq)
	if err != nil {
		log.Fatalf("MCP Initialize handshake failed: %v", err)
	}
	fmt.Printf("[INITIALIZE] Handshake successful! Server name: %s, Protocol: %s\n",
		initResult.ServerInfo.Name, initResult.ProtocolVersion)

	// Step 3: List Tools
	toolsResult, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		log.Fatalf("ListTools failed: %v", err)
	}
	fmt.Printf("[TOOLS/LIST] Discovered %d tool(s) through Bifrost gateway:\n", len(toolsResult.Tools))
	var scanToolName string
	for _, t := range toolsResult.Tools {
		fmt.Printf("  - Tool: %s (Description: %s)\n", t.Name, t.Description)
		if t.Name == "mock_scan" || t.Name == "mock_security_server-mock_scan" {
			scanToolName = t.Name
		}
	}

	if scanToolName == "" {
		log.Fatalf("Required scan tool not found in Bifrost tools list!")
	}
	fmt.Printf("[TARGET TOOL] Using resolved tool name: %s\n\n", scanToolName)

	// =========================================================================
	// TEST A: Allowed target (172.28.0.100:3000)
	// =========================================================================
	targetA := "http://172.28.0.100:3000"
	fmt.Println("=================================================================")
	fmt.Printf("TEST A: Calling tool %s with target: %s\n", scanToolName, targetA)
	fmt.Println("Expected: Allowed by ScopeEnforcer, executed by mock server.")
	fmt.Println("=================================================================")

	callReqA := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: scanToolName,
			Arguments: map[string]any{
				"target": targetA,
			},
		},
	}
	resA, errA := mcpClient.CallTool(ctx, callReqA)
	if errA != nil {
		fmt.Printf("TEST A RPC Error: %v\n", errA)
	} else {
		isErr := resA.IsError
		fmt.Printf("TEST A IsError: %v\n", isErr)
		for idx, c := range resA.Content {
			if textContent, ok := c.(mcp.TextContent); ok {
				fmt.Printf("TEST A Content[%d]: %s\n", idx, textContent.Text)
			}
		}
	}

	statsA, err := getUpstreamStats()
	if err != nil {
		log.Fatalf("Failed to query stats after Test A: %v", err)
	}
	fmt.Printf("Upstream mock server total requests received after TEST A: %d (Delta: +%d)\n\n",
		statsA.RequestsReceived, statsA.RequestsReceived-initStats.RequestsReceived)

	// =========================================================================
	// TEST B: Blocked target (192.0.2.10:3000)
	// =========================================================================
	targetB := "http://192.0.2.10:3000"
	fmt.Println("=================================================================")
	fmt.Printf("TEST B: Calling tool %s with target: %s\n", scanToolName, targetB)
	fmt.Println("Expected: Blocked by ScopeEnforcerPlugin (HTTP 403 / Tool error).")
	fmt.Println("Verify: Mock server must NEVER receive this request (Delta = 0).")
	fmt.Println("=================================================================")

	callReqB := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: scanToolName,
			Arguments: map[string]any{
				"target": targetB,
			},
		},
	}
	resB, errB := mcpClient.CallTool(ctx, callReqB)
	if errB != nil {
		fmt.Printf("TEST B RPC Error: %v\n", errB)
	} else {
		isErr := resB.IsError
		fmt.Printf("TEST B IsError: %v\n", isErr)
		for idx, c := range resB.Content {
			if textContent, ok := c.(mcp.TextContent); ok {
				fmt.Printf("TEST B Content[%d]: %s\n", idx, textContent.Text)
			}
		}
	}

	statsB, err := getUpstreamStats()
	if err != nil {
		log.Fatalf("Failed to query stats after Test B: %v", err)
	}
	fmt.Printf("Upstream mock server total requests received after TEST B: %d (Delta: +%d)\n\n",
		statsB.RequestsReceived, statsB.RequestsReceived-statsA.RequestsReceived)

	// =========================================================================
	// FINAL VERIFICATION SUMMARY
	// =========================================================================
	testAPassed := (errA == nil && !resA.IsError && (statsA.RequestsReceived-initStats.RequestsReceived == 1))
	testBPassed := ((errB != nil || (resB != nil && resB.IsError)) && (statsB.RequestsReceived-statsA.RequestsReceived == 0))

	fmt.Println("=================================================================")
	fmt.Println("INTEGRATION TEST SUMMARY:")
	fmt.Printf("  TEST A (Allowed in-scope target): %v\n", map[bool]string{true: "PASSED", false: "FAILED"}[testAPassed])
	fmt.Printf("  TEST B (Blocked out-of-scope target): %v\n", map[bool]string{true: "PASSED", false: "FAILED"}[testBPassed])
	fmt.Printf("  ScopeEnforcer Dropped Request Upstream Protection: %v\n", map[bool]string{true: "VERIFIED (Mock server received 0 requests for Test B)", false: "FAILED"}[statsB.RequestsReceived == statsA.RequestsReceived])
	fmt.Println("=================================================================")

	if !testAPassed || !testBPassed {
		os.Exit(1)
	}
}
