package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
	"databricks-account-api-proxy/internal/policy"
)

func setupMockOAuthAndPolicy(t *testing.T, handler http.HandlerFunc) (*policy.SPNManagerPolicy, *policy.NCCWorkspaceAdminPolicy, *config.Config) {
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cfg := &config.Config{
		DatabricksAccountID:    "acc-12345",
		DatabricksAccountsHost: server.URL,
		ProxyClientID:          "test-client-id",
		ProxyClientSecret:      "test-client-secret",
		CacheTTL:               1 * time.Minute,
	}

	tokenMgr := auth.NewAdminTokenManager(cfg, server.Client())
	spnPol := policy.NewSPNManagerPolicy(cfg, tokenMgr, server.Client())
	nccPol := policy.NewNCCWorkspaceAdminPolicy(cfg, tokenMgr, server.Client())

	return spnPol, nccPol, cfg
}

func TestSPNManagerPolicy(t *testing.T) {
	targetSPN := "target-spn-uuid-001"
	accountID := "acc-12345"

	tests := []struct {
		name          string
		caller        *models.CallerIdentity
		ruleSet       models.AccessControlRuleSet
		expectAllowed bool
		expectedError string
	}{
		{
			name: "Direct SPN manager match",
			caller: &models.CallerIdentity{
				PrincipalID:        "caller-spn-111",
				IsServicePrincipal: true,
			},
			ruleSet: models.AccessControlRuleSet{
				GrantRules: []models.GrantRule{
					{
						Role:       "roles/servicePrincipal.manager",
						Principals: []string{"servicePrincipals/caller-spn-111"},
					},
				},
			},
			expectAllowed: true,
		},
		{
			name: "Group-inherited SPN manager match",
			caller: &models.CallerIdentity{
				PrincipalID:        "caller-user-222",
				Email:              "caller@example.com",
				Groups:             []string{"data-engineers", "spn-operators"},
				IsServicePrincipal: false,
			},
			ruleSet: models.AccessControlRuleSet{
				GrantRules: []models.GrantRule{
					{
						Role:       "roles/servicePrincipal.manager",
						Principals: []string{"groups/spn-operators"},
					},
				},
			},
			expectAllowed: true,
		},
		{
			name: "Denied when caller is only servicePrincipal.user",
			caller: &models.CallerIdentity{
				PrincipalID:        "caller-spn-333",
				IsServicePrincipal: true,
			},
			ruleSet: models.AccessControlRuleSet{
				GrantRules: []models.GrantRule{
					{
						Role:       "roles/servicePrincipal.user",
						Principals: []string{"servicePrincipals/caller-spn-333"},
					},
					{
						Role:       "roles/servicePrincipal.manager",
						Principals: []string{"servicePrincipals/other-spn"},
					},
				},
			},
			expectAllowed: false,
			expectedError: "does not have role 'roles/servicePrincipal.manager'",
		},
		{
			name: "Denied when caller is unrelated",
			caller: &models.CallerIdentity{
				PrincipalID:        "stranger-user",
				Email:              "stranger@example.com",
				Groups:             []string{"interns"},
				IsServicePrincipal: false,
			},
			ruleSet: models.AccessControlRuleSet{
				GrantRules: []models.GrantRule{
					{
						Role:       "roles/servicePrincipal.manager",
						Principals: []string{"users/authorized-admin@example.com"},
					},
				},
			},
			expectAllowed: false,
			expectedError: "does not have role 'roles/servicePrincipal.manager'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				// Handle OAuth token request
				if r.URL.Path == "/oidc/v1/token" {
					_ = json.NewEncoder(w).Encode(auth.TokenResponse{
						AccessToken: "mock-admin-token",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					})
					return
				}

				// Handle Access Control Rule Set query
				if strings.Contains(r.URL.Path, "/access-control/rule-sets/") {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(tc.ruleSet)
					return
				}

				http.NotFound(w, r)
			}

			spnPol, _, _ := setupMockOAuthAndPolicy(t, handler)
			allowed, reason, err := spnPol.VerifySPNManager(context.Background(), accountID, targetSPN, tc.caller)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.expectAllowed {
				t.Fatalf("expected allowed=%v, got %v (reason: %s)", tc.expectAllowed, allowed, reason)
			}
			if !tc.expectAllowed && tc.expectedError != "" {
				if !strings.Contains(reason, tc.expectedError) {
					t.Errorf("expected denial reason to contain '%s', got '%s'", tc.expectedError, reason)
				}
			}
		})
	}
}

func TestNCCWorkspaceAdminPolicy(t *testing.T) {
	accountID := "acc-12345"
	nccID := "ncc-test-999"
	workspaceID := "ws-100"

	tests := []struct {
		name          string
		caller        *models.CallerIdentity
		targetWS      models.Workspace
		allWorkspaces []models.Workspace
		wsAdmins      []string // usernames/appIds that are in 'admins'
		expectAllowed bool
		expectedError string
	}{
		{
			name: "Allowed: 1:1 bound NCC and caller is Workspace Admin",
			caller: &models.CallerIdentity{
				PrincipalID:        "admin-user@example.com",
				Email:              "admin-user@example.com",
				Groups:             []string{"admins"},
				IsServicePrincipal: false,
			},
			targetWS: models.Workspace{
				WorkspaceID:                 100,
				DeploymentName:              "ws-100",
				NetworkConnectivityConfigID: nccID,
			},
			allWorkspaces: []models.Workspace{
				{WorkspaceID: 100, NetworkConnectivityConfigID: nccID},
				{WorkspaceID: 200, NetworkConnectivityConfigID: "other-ncc"},
			},
			wsAdmins:      []string{"admin-user@example.com"},
			expectAllowed: true,
		},
		{
			name: "Denied: NCC shared with second workspace (blast radius prevention)",
			caller: &models.CallerIdentity{
				PrincipalID:        "admin-user@example.com",
				Email:              "admin-user@example.com",
				Groups:             []string{"admins"},
				IsServicePrincipal: false,
			},
			targetWS: models.Workspace{
				WorkspaceID:                 100,
				DeploymentName:              "ws-100",
				NetworkConnectivityConfigID: nccID,
			},
			allWorkspaces: []models.Workspace{
				{WorkspaceID: 100, NetworkConnectivityConfigID: nccID},
				{WorkspaceID: 200, NetworkConnectivityConfigID: nccID}, // Shared!
			},
			wsAdmins:      []string{"admin-user@example.com"},
			expectAllowed: false,
			expectedError: "shared across multiple workspaces",
		},
		{
			name: "Denied: Workspace is not bound to the specified NCC",
			caller: &models.CallerIdentity{
				PrincipalID:        "admin-user@example.com",
				Groups:             []string{"admins"},
				IsServicePrincipal: false,
			},
			targetWS: models.Workspace{
				WorkspaceID:                 100,
				DeploymentName:              "ws-100",
				NetworkConnectivityConfigID: "unrelated-ncc",
			},
			allWorkspaces: []models.Workspace{
				{WorkspaceID: 100, NetworkConnectivityConfigID: "unrelated-ncc"},
			},
			wsAdmins:      []string{"admin-user@example.com"},
			expectAllowed: false,
			expectedError: "is not bound to NCC",
		},
		{
			name: "Denied: Caller is regular workspace user (not in admins)",
			caller: &models.CallerIdentity{
				PrincipalID:        "regular-user@example.com",
				Email:              "regular-user@example.com",
				Groups:             []string{"users"}, // Not in 'admins'
				IsServicePrincipal: false,
			},
			targetWS: models.Workspace{
				WorkspaceID:                 100,
				DeploymentName:              "ws-100",
				NetworkConnectivityConfigID: nccID,
			},
			allWorkspaces: []models.Workspace{
				{WorkspaceID: 100, NetworkConnectivityConfigID: nccID},
			},
			wsAdmins:      []string{"admin-user@example.com"},
			expectAllowed: false,
			expectedError: "not an admin of workspace",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				// Handle OAuth token
				if r.URL.Path == "/oidc/v1/token" {
					_ = json.NewEncoder(w).Encode(auth.TokenResponse{
						AccessToken: "mock-admin-token",
						TokenType:   "Bearer",
						ExpiresIn:   3600,
					})
					return
				}

				// Check 1: Workspace details
				if r.URL.Path == "/api/2.0/accounts/"+accountID+"/workspaces/"+workspaceID {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(tc.targetWS)
					return
				}

				// Check 2: All workspaces
				if r.URL.Path == "/api/2.0/accounts/"+accountID+"/workspaces" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(tc.allWorkspaces)
					return
				}

				// Check 3: Workspace SCIM query (if triggered)
				if strings.Contains(r.URL.Path, "/api/2.0/preview/scim/v2/") {
					var groups []models.SCIMGroup
					for _, adm := range tc.wsAdmins {
						if adm == tc.caller.PrincipalID {
							groups = append(groups, models.SCIMGroup{Display: "admins", Value: "admins"})
						}
					}
					resp := models.SCIMSearchResponse{
						TotalResults: 1,
						Resources: []models.SCIMMeResponse{
							{
								ID:       "123",
								UserName: tc.caller.PrincipalID,
								Groups:   groups,
							},
						},
					}
					w.Header().Set("Content-Type", "application/scim+json")
					_ = json.NewEncoder(w).Encode(resp)
					return
				}

				http.NotFound(w, r)
			}

			_, nccPol, _ := setupMockOAuthAndPolicy(t, handler)
			allowed, reason, err := nccPol.VerifyNCCWorkspaceAdmin(context.Background(), accountID, nccID, workspaceID, tc.caller)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.expectAllowed {
				t.Fatalf("expected allowed=%v, got %v (reason: %s)", tc.expectAllowed, allowed, reason)
			}
			if !tc.expectAllowed && tc.expectedError != "" {
				if !strings.Contains(reason, tc.expectedError) {
					t.Errorf("expected denial reason to contain '%s', got '%s'", tc.expectedError, reason)
				}
			}
		})
	}
}
