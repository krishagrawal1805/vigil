package scopepolicy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// PolicyViolationError indicates an HTTP request or redirect was blocked by the scope enforcer.
type PolicyViolationError struct {
	Phase   string // "request" or "redirect"
	Method  string
	URL     string
	Message string
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("FineGrainedScopeEnforcer: %s blocked [%s %s] - %s", e.Phase, e.Method, e.URL, e.Message)
}

// ControlledTransport wraps an http.RoundTripper with fine-grained scope enforcement on every request.
type ControlledTransport struct {
	Enforcer         *FineGrainedScopeEnforcer
	BaseRoundTripper http.RoundTripper
}

func (t *ControlledTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. Enforce policy BEFORE dialing or transmitting any bytes
	if err := t.Enforcer.CheckRequest(req.Method, req.URL.String()); err != nil {
		return nil, &PolicyViolationError{
			Phase:   "request",
			Method:  req.Method,
			URL:     req.URL.String(),
			Message: err.Error(),
		}
	}

	base := t.BaseRoundTripper
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(req)
}

// NewControlledHTTPClient creates a hardened http.Client that enforces fine-grained policy
// on every request and every HTTP redirect.
func NewControlledHTTPClient(enforcer *FineGrainedScopeEnforcer, labTargetRewrite bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	baseTransport := &http.Transport{
		Proxy:                 nil, // Prevent unintended proxy bypass
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// For testing in local environments where 172.28.0.100 is the lab target:
			// route TCP connection to local test mock app on 127.0.0.1 while preserving original Host headers
			if labTargetRewrite {
				host, port, err := net.SplitHostPort(addr)
				if err == nil && host == "172.28.0.100" {
					addr = net.JoinHostPort("127.0.0.1", port)
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	transport := &ControlledTransport{
		Enforcer:         enforcer,
		BaseRoundTripper: baseTransport,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}

			// Intercept and evaluate the redirect destination BEFORE following
			redirectURL := req.URL.String()
			redirectMethod := req.Method

			if err := enforcer.CheckRequest(redirectMethod, redirectURL); err != nil {
				return &PolicyViolationError{
					Phase:   "redirect",
					Method:  redirectMethod,
					URL:     redirectURL,
					Message: fmt.Sprintf("redirect destination prohibited: %v", err),
				}
			}

			// Ensure original security headers are not leaked to external hosts
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
			}

			return nil
		},
	}

	return client
}

// SafeHTTPRequest executes an HTTP request using the controlled client and returns a clean result summary.
type SafeHTTPResult struct {
	StatusCode int               `json:"status_code"`
	Status     string            `json:"status"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	FinalURL   string            `json:"final_url"`
}

func ExecuteSafeRequest(client *http.Client, method, targetURL string) (*SafeHTTPResult, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("User-Agent", "VIGIL-Security-Scanner/1.0 (Scope-Enforced)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	bodyStr := string(buf[:n])

	headerMap := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headerMap[k] = v[0]
		}
	}

	return &SafeHTTPResult{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    headerMap,
		Body:       bodyStr,
		FinalURL:   resp.Request.URL.String(),
	}, nil
}

