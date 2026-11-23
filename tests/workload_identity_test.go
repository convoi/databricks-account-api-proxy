package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
	"databricks-account-api-proxy/pkg/client"
)

func TestExchangeWorkloadIdentityToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/v1/token" {
			_ = r.ParseForm()
			if r.FormValue("client_assertion") == "mock-oidc-jwt" &&
				r.FormValue("client_id") == "app-client-123" &&
				r.FormValue("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"exchanged-databricks-token-abc"}`))
				return
			}
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	endpoint := server.URL + "/oidc/v1/token"
	token, err := client.ExchangeWorkloadIdentityToken(context.Background(), server.Client(), endpoint, "app-client-123", "mock-oidc-jwt")
	if err != nil {
		t.Fatalf("unexpected exchange error: %v", err)
	}

	if token != "exchanged-databricks-token-abc" {
		t.Fatalf("expected exchanged-databricks-token-abc, got %s", token)
	}
}

func TestCallerValidator_WorkloadIdentityExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token exchange endpoint
		if r.URL.Path == "/oidc/v1/token" {
			_ = r.ParseForm()
			if r.FormValue("client_assertion") == "raw.oidc.jwt" && r.FormValue("client_id") == "caller-spn-999" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"databricks-access-token-999"}`))
				return
			}
			http.Error(w, `{"error":"invalid_assertion"}`, http.StatusBadRequest)
			return
		}

		// SCIM Me endpoint
		if r.URL.Path == "/api/2.0/preview/scim/v2/Me" {
			authHdr := r.Header.Get("Authorization")
			// Reject the raw external OIDC token, only accept exchanged Databricks token
			if authHdr == "Bearer raw.oidc.jwt" {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}
			if authHdr == "Bearer databricks-access-token-999" {
				_ = json.NewEncoder(w).Encode(models.SCIMMeResponse{
					ID:            "999",
					ApplicationID: "caller-spn-999",
					DisplayName:   "Workload Identity SPN",
					Active:        true,
					Groups: []models.SCIMGroup{
						{Display: "admins", Value: "admins"},
					},
				})
				return
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := &config.Config{DatabricksAccountsHost: server.URL}
	validator := auth.NewCallerValidator(cfg, server.Client())

	// Call ValidateCallerWithClientID passing raw OIDC JWT assertion
	caller, err := validator.ValidateCallerWithClientID(context.Background(), "raw.oidc.jwt", server.URL, "caller-spn-999")
	if err != nil {
		t.Fatalf("unexpected error validating workload identity caller: %v", err)
	}

	if caller.PrincipalID != "caller-spn-999" {
		t.Errorf("expected principal ID caller-spn-999, got %s", caller.PrincipalID)
	}
	if !caller.IsServicePrincipal {
		t.Errorf("expected IsServicePrincipal=true")
	}
	if !caller.HasGroup("admins") {
		t.Errorf("expected caller to have admins group")
	}
}
