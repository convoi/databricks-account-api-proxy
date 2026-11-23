package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"databricks-account-api-proxy/internal/audit"
	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
	"databricks-account-api-proxy/internal/policy"
	"databricks-account-api-proxy/internal/proxy"
	"databricks-account-api-proxy/internal/whitelist"
)

func setupTestProxy(t *testing.T, upstreamHandler http.HandlerFunc) (*httptest.Server, *httptest.Server, *bytes.Buffer) {
	upstreamServer := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstreamServer.Close)

	cfg := &config.Config{
		DatabricksAccountID:    "test-acc-1",
		DatabricksAccountsHost: upstreamServer.URL,
		ProxyClientID:          "proxy-spn-client-id",
		ProxyClientSecret:      "proxy-spn-client-secret",
		ProxyListenAddr:        ":0",
		CacheTTL:               500 * time.Millisecond,
	}

	auditBuf := &bytes.Buffer{}
	auditLogger := audit.NewLogger(auditBuf)

	httpClient := upstreamServer.Client()
	tokenMgr := auth.NewAdminTokenManager(cfg, httpClient)
	validator := auth.NewCallerValidator(cfg, httpClient)
	spnPol := policy.NewSPNManagerPolicy(cfg, tokenMgr, httpClient)
	nccPol := policy.NewNCCWorkspaceAdminPolicy(cfg, tokenMgr, httpClient)

	proxyServer := proxy.NewProxyServer(
		cfg,
		tokenMgr,
		validator,
		spnPol,
		nccPol,
		nil,
		auditLogger,
		httpClient,
	)

	router := proxyServer.SetupRoutes()
	proxyHttpServer := httptest.NewServer(router)
	t.Cleanup(proxyHttpServer.Close)

	return proxyHttpServer, upstreamServer, auditBuf
}

func TestProxy_BlockedNonAllowlistedEndpoints(t *testing.T) {
	proxyServer, _, auditBuf := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 1. DELETE /api/2.0/accounts/{account_id}/servicePrincipals/{target_spn_id}
	// (Only GET is allowlisted on the SPN base resource)
	req, _ := http.NewRequest(http.MethodDelete,
		proxyServer.URL+"/api/2.0/accounts/test-acc-1/servicePrincipals/spn-123", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")

	resp, err := proxyServer.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected method not allowed/forbidden for DELETE SPN, got %d", resp.StatusCode)
	}

	// 2. Completely arbitrary endpoint
	req2, _ := http.NewRequest(http.MethodGet,
		proxyServer.URL+"/api/2.0/accounts/test-acc-1/clusters", nil)
	resp2, err := proxyServer.Client().Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for arbitrary endpoint, got %d", resp2.StatusCode)
	}

	// Check audit log output for default deny
	logs := auditBuf.String()
	if !strings.Contains(logs, `"decision":"DENY"`) {
		t.Errorf("expected DENY in audit logs for blocked endpoint, got: %s", logs)
	}
	if strings.Contains(logs, "dummy-token") {
		t.Errorf("sensitive token leaked into audit log!")
	}
}

func TestProxy_SPNFederationPolicyForwardingAndSanitization(t *testing.T) {
	var receivedUpstreamAuthHeader string
	var receivedUpstreamCustomHeader string

	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		// Admin token acquisition
		if r.URL.Path == "/oidc/v1/token" {
			_ = json.NewEncoder(w).Encode(auth.TokenResponse{
				AccessToken: "privileged-account-admin-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
			return
		}

		// Caller introspection (GET /api/2.0/preview/scim/v2/Me)
		if r.URL.Path == "/api/2.0/preview/scim/v2/Me" {
			callerAuth := r.Header.Get("Authorization")
			if callerAuth != "Bearer valid-caller-token" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(models.SCIMMeResponse{
				ID:            "caller-numeric-99",
				ApplicationID: "caller-spn-uuid-99",
				DisplayName:   "Caller SPN",
				Active:        true,
			})
			return
		}

		// Rule-set query
		if strings.Contains(r.URL.Path, "/access-control/rule-sets/") {
			_ = json.NewEncoder(w).Encode(models.AccessControlRuleSet{
				GrantRules: []models.GrantRule{
					{
						Role:       "roles/servicePrincipal.manager",
						Principals: []string{"servicePrincipals/caller-spn-uuid-99"},
					},
				},
			})
			return
		}

		// The actual proxied request: POST federationPolicies
		if strings.Contains(r.URL.Path, "/federationPolicies") {
			receivedUpstreamAuthHeader = r.Header.Get("Authorization")
			receivedUpstreamCustomHeader = r.Header.Get("X-Custom-Request-Header")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"policy_id":"new-policy-id-123","name":"my-federation-policy"}`))
			return
		}

		http.NotFound(w, r)
	}

	proxyServer, upstreamServer, auditBuf := setupTestProxy(t, upstreamHandler)

	postBody := []byte(`{"name":"my-federation-policy","issuer":"https://token.actions.githubusercontent.com","subject":"repo:org/repo:ref:refs/heads/main"}`)
	req, _ := http.NewRequest(http.MethodPost,
		proxyServer.URL+"/api/2.0/accounts/test-acc-1/servicePrincipals/target-spn-001/federationPolicies",
		bytes.NewReader(postBody))

	req.Header.Set("Authorization", "Bearer valid-caller-token")
	req.Header.Set("X-Databricks-Workspace-Url", upstreamServer.URL) // Route SCIM to mock server
	req.Header.Set("X-Custom-Request-Header", "custom-header-value")
	req.Header.Set("Content-Type", "application/json")

	resp, err := proxyServer.Client().Do(req)
	if err != nil {
		t.Fatalf("request to proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201 Created from proxy, got %d: %s", resp.StatusCode, string(b))
	}

	// Verify Header Sanitization:
	// Upstream received the privileged Admin token, NOT the caller token
	if receivedUpstreamAuthHeader != "Bearer privileged-account-admin-token" {
		t.Errorf("expected upstream Authorization to be injected admin token, got: '%s'", receivedUpstreamAuthHeader)
	}
	if receivedUpstreamCustomHeader != "custom-header-value" {
		t.Errorf("expected upstream to receive custom header, got: '%s'", receivedUpstreamCustomHeader)
	}

	// Verify audit log has ALLOW and masks tokens
	logOutput := auditBuf.String()
	if !strings.Contains(logOutput, `"decision":"ALLOW"`) {
		t.Errorf("expected ALLOW decision in audit log, got: %s", logOutput)
	}
	if strings.Contains(logOutput, "valid-caller-token") || strings.Contains(logOutput, "privileged-account-admin-token") {
		t.Errorf("audit log contains raw tokens: %s", logOutput)
	}
}

func TestProxy_NCCPrivateEndpointRulesForwarding(t *testing.T) {
	accountID := "test-acc-1"
	nccID := "ncc-prod-1"
	workspaceID := "101"

	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		// Admin token
		if r.URL.Path == "/oidc/v1/token" {
			_ = json.NewEncoder(w).Encode(auth.TokenResponse{
				AccessToken: "privileged-account-admin-token",
				ExpiresIn:   3600,
			})
			return
		}

		// Caller introspection
		if r.URL.Path == "/api/2.0/preview/scim/v2/Me" {
			_ = json.NewEncoder(w).Encode(models.SCIMMeResponse{
				ID:          "ws-admin-1",
				UserName:    "wsadmin@example.com",
				DisplayName: "Workspace Admin",
				Active:      true,
				Groups: []models.SCIMGroup{
					{Display: "admins", Value: "admins"},
				},
			})
			return
		}

		// Workspace details
		if r.URL.Path == "/api/2.0/accounts/"+accountID+"/workspaces/"+workspaceID {
			_ = json.NewEncoder(w).Encode(models.Workspace{
				WorkspaceID:                 101,
				DeploymentName:              "ws-101",
				NetworkConnectivityConfigID: nccID,
			})
			return
		}

		// All workspaces query
		if r.URL.Path == "/api/2.0/accounts/"+accountID+"/workspaces" {
			_ = json.NewEncoder(w).Encode([]models.Workspace{
				{WorkspaceID: 101, NetworkConnectivityConfigID: nccID},
				{WorkspaceID: 202, NetworkConnectivityConfigID: "other-ncc"},
			})
			return
		}

		// Proxied NCC Private Endpoint Rule creation
		if strings.Contains(r.URL.Path, "/private-endpoint-rules") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"rule_id":"rule-abc-123","endpoint_name":"test-pe"}`))
			return
		}

		http.NotFound(w, r)
	}

	proxyServer, upstreamServer, auditBuf := setupTestProxy(t, upstreamHandler)

	body := []byte(`{"resource_id":"/subscriptions/.../storageAccounts/sa1","group_id":"blob"}`)
	req, _ := http.NewRequest(http.MethodPost,
		proxyServer.URL+"/api/2.0/accounts/test-acc-1/network-connectivity-configs/ncc-prod-1/private-endpoint-rules",
		bytes.NewReader(body))

	req.Header.Set("Authorization", "Bearer valid-caller-token")
	req.Header.Set("X-Databricks-Workspace-Id", workspaceID)
	req.Header.Set("X-Databricks-Workspace-Url", upstreamServer.URL)
	req.Header.Set("Content-Type", "application/json")

	resp, err := proxyServer.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201 Created from proxy, got %d: %s", resp.StatusCode, string(b))
	}

	logOutput := auditBuf.String()
	if !strings.Contains(logOutput, `"policy_evaluated":"ncc_workspace_admin"`) {
		t.Errorf("expected policy_evaluated to be ncc_workspace_admin, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"decision":"ALLOW"`) {
		t.Errorf("expected ALLOW decision, got: %s", logOutput)
	}
}

func TestProxy_CallingSPNWorkspaceWhitelist(t *testing.T) {
	callingSPN := "caller-spn-authorized-101"
	allowedWS := "101"
	disallowedWS := "999"

	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/v1/token" {
			_ = json.NewEncoder(w).Encode(auth.TokenResponse{
				AccessToken: "privileged-admin-token",
				ExpiresIn:   3600,
			})
			return
		}

		if r.URL.Path == "/api/2.0/preview/scim/v2/Me" {
			_ = json.NewEncoder(w).Encode(models.SCIMMeResponse{
				ID:            "caller-numeric-101",
				ApplicationID: callingSPN,
				DisplayName:   "Authorized SPN",
				Active:        true,
				Groups: []models.SCIMGroup{
					{Display: "admins", Value: "admins"},
				},
			})
			return
		}

		// Workspace lookup for workspace 101
		if strings.Contains(r.URL.Path, "/workspaces/101") {
			_ = json.NewEncoder(w).Encode(models.Workspace{
				WorkspaceID:                 101,
				DeploymentName:              "ws-101",
				NetworkConnectivityConfigID: "ncc-101",
			})
			return
		}

		// All workspaces query
		if strings.HasSuffix(r.URL.Path, "/workspaces") {
			_ = json.NewEncoder(w).Encode([]models.Workspace{
				{WorkspaceID: 101, NetworkConnectivityConfigID: "ncc-101"},
			})
			return
		}

		if strings.Contains(r.URL.Path, "/private-endpoint-rules") {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"rule_id":"rule-ok"}`))
			return
		}

		http.NotFound(w, r)
	}

	upstreamServer := httptest.NewServer(http.HandlerFunc(upstreamHandler))
	t.Cleanup(upstreamServer.Close)

	// Create test whitelist config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configYaml := `
spn_workspace_whitelist:
  "` + callingSPN + `":
    - "` + allowedWS + `"
`
	if err := os.WriteFile(configPath, []byte(configYaml), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := &config.Config{
		DatabricksAccountID:    "test-acc",
		DatabricksAccountsHost: upstreamServer.URL,
		ProxyClientID:          "client",
		ProxyClientSecret:      "secret",
		ConfigFile:             configPath,
	}

	wl, err := whitelist.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("load whitelist failed: %v", err)
	}

	auditBuf := &bytes.Buffer{}
	auditLogger := audit.NewLogger(auditBuf)
	httpClient := upstreamServer.Client()
	tokenMgr := auth.NewAdminTokenManager(cfg, httpClient)
	validator := auth.NewCallerValidator(cfg, httpClient)
	spnPol := policy.NewSPNManagerPolicy(cfg, tokenMgr, httpClient)
	nccPol := policy.NewNCCWorkspaceAdminPolicy(cfg, tokenMgr, httpClient)

	proxyServer := proxy.NewProxyServer(
		cfg,
		tokenMgr,
		validator,
		spnPol,
		nccPol,
		wl,
		auditLogger,
		httpClient,
	)

	proxyHttpServer := httptest.NewServer(proxyServer.SetupRoutes())
	t.Cleanup(proxyHttpServer.Close)

	// Case 1: Calling SPN attempts to manage unauthorized workspace 999
	reqDisallowed, _ := http.NewRequest(http.MethodPost,
		proxyHttpServer.URL+"/api/2.0/accounts/test-acc/network-connectivity-configs/ncc-101/private-endpoint-rules",
		bytes.NewReader([]byte(`{}`)))
	reqDisallowed.Header.Set("Authorization", "Bearer caller-token")
	reqDisallowed.Header.Set("X-Databricks-Workspace-Id", disallowedWS)
	reqDisallowed.Header.Set("X-Databricks-Workspace-Url", upstreamServer.URL)
	reqDisallowed.Header.Set("Content-Type", "application/json")

	resp1, err := proxyHttpServer.Client().Do(reqDisallowed)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disallowed workspace, got %d", resp1.StatusCode)
	}

	logs := auditBuf.String()
	if !strings.Contains(logs, `"policy_evaluated":"spn_workspace_whitelist"`) {
		t.Errorf("expected audit log to record spn_workspace_whitelist denial, got: %s", logs)
	}
	if !strings.Contains(logs, `"decision":"DENY"`) {
		t.Errorf("expected audit log to record DENY decision")
	}

	// Case 2: Calling SPN attempts to manage authorized workspace 101
	auditBuf.Reset()
	reqAllowed, _ := http.NewRequest(http.MethodPost,
		proxyHttpServer.URL+"/api/2.0/accounts/test-acc/network-connectivity-configs/ncc-101/private-endpoint-rules",
		bytes.NewReader([]byte(`{}`)))
	reqAllowed.Header.Set("Authorization", "Bearer caller-token")
	reqAllowed.Header.Set("X-Databricks-Workspace-Id", allowedWS)
	reqAllowed.Header.Set("X-Databricks-Workspace-Url", upstreamServer.URL)
	reqAllowed.Header.Set("Content-Type", "application/json")

	resp2, err := proxyHttpServer.Client().Do(reqAllowed)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 201 Created for allowed workspace, got %d: %s", resp2.StatusCode, string(b))
	}
}

func TestProxy_AccountIDPinningAndSSRFProtection(t *testing.T) {
	proxyServer, _, auditBuf := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 1. Account ID mismatch (setupTestProxy configures DatabricksAccountID = "test-acc-1")
	req1, _ := http.NewRequest(http.MethodGet,
		proxyServer.URL+"/api/2.0/accounts/wrong-account-id/servicePrincipals/spn-1", nil)
	req1.Header.Set("Authorization", "Bearer valid-token")
	req1.Header.Set("X-Databricks-Workspace-Url", "https://my-ws.cloud.databricks.com")

	resp1, err := proxyServer.Client().Do(req1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for mismatched account_id, got %d", resp1.StatusCode)
	}
	if !strings.Contains(auditBuf.String(), "does not match proxy's configured account_id") {
		t.Errorf("expected account_id mismatch reason in audit log, got: %s", auditBuf.String())
	}

	// 2. SSRF attempt via untrusted X-Databricks-Workspace-Url
	auditBuf.Reset()
	req2, _ := http.NewRequest(http.MethodGet,
		proxyServer.URL+"/api/2.0/accounts/test-acc-1/servicePrincipals/spn-1", nil)
	req2.Header.Set("Authorization", "Bearer valid-token")
	req2.Header.Set("X-Databricks-Workspace-Url", "http://169.254.169.254/latest/meta-data")

	resp2, err := proxyServer.Client().Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for untrusted SSRF workspace URL, got %d", resp2.StatusCode)
	}
	if !strings.Contains(auditBuf.String(), "untrusted workspace URL host") {
		t.Errorf("expected SSRF host rejection in audit log, got: %s", auditBuf.String())
	}
}

