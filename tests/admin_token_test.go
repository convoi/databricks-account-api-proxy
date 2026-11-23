package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
)

func TestAdminTokenManager_Refresh(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/v1/token" {
			current := atomic.AddInt32(&callCount, 1)
			token := "token-1"
			expiresIn := int64(100) // 100 seconds
			if current > 1 {
				token = "token-2"
			}
			_ = json.NewEncoder(w).Encode(auth.TokenResponse{
				AccessToken: token,
				TokenType:   "Bearer",
				ExpiresIn:   expiresIn,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := &config.Config{
		DatabricksAccountsHost: server.URL,
		ProxyClientID:          "client-id",
		ProxyClientSecret:      "client-secret",
	}

	mgr := auth.NewAdminTokenManager(cfg, server.Client())

	tok1, err := mgr.GetToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1 != "token-1" {
		t.Fatalf("expected token-1, got %s", tok1)
	}

	// Repeated call within validity period should return cached token without new HTTP call
	tokCached, err := mgr.GetToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokCached != "token-1" {
		t.Fatalf("expected cached token-1, got %s", tokCached)
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Fatalf("expected 1 call to token endpoint, got %d", callCount)
	}
}

func TestAdminTokenManager_WorkloadIdentity(t *testing.T) {
	var receivedGrantType, receivedAssertionType, receivedAssertion, receivedClientID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/v1/token" {
			_ = r.ParseForm()
			receivedGrantType = r.FormValue("grant_type")
			receivedAssertionType = r.FormValue("client_assertion_type")
			receivedAssertion = r.FormValue("client_assertion")
			receivedClientID = r.FormValue("client_id")

			_ = json.NewEncoder(w).Encode(auth.TokenResponse{
				AccessToken: "federated-admin-token-xyz",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := &config.Config{
		DatabricksAccountsHost: server.URL,
		ProxyClientID:          "spn-workload-id-123",
		ProxyOIDCToken:         "ey.external-oidc-jwt.signature",
	}

	mgr := auth.NewAdminTokenManager(cfg, server.Client())
	tok, err := mgr.GetToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tok != "federated-admin-token-xyz" {
		t.Fatalf("expected federated-admin-token-xyz, got %s", tok)
	}
	if receivedGrantType != "client_credentials" {
		t.Errorf("expected grant_type=client_credentials, got %s", receivedGrantType)
	}
	if receivedAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("expected client_assertion_type=jwt-bearer, got %s", receivedAssertionType)
	}
	if receivedAssertion != "ey.external-oidc-jwt.signature" {
		t.Errorf("expected assertion matching OIDC token, got %s", receivedAssertion)
	}
	if receivedClientID != "spn-workload-id-123" {
		t.Errorf("expected client_id=spn-workload-id-123, got %s", receivedClientID)
	}
}
