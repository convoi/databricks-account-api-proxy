package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/models"
)

// SetupRoutes registers explicit allowlisted routes on a Chi router with strict default-deny.
func (s *ProxyServer) SetupRoutes() chi.Router {
	r := chi.NewRouter()

	// Default Deny for unknown paths
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		reqID := GenerateRequestID()
		s.auditLogger.Record(reqID, nil, "unknown", req.Method, req.URL.Path, "none",
			models.DecisionDeny, "route not allowlisted (default deny)", http.StatusNotFound)
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "route not allowlisted by proxy"})
	})

	// Default Deny for non-allowlisted HTTP methods on known paths
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		reqID := GenerateRequestID()
		s.auditLogger.Record(reqID, nil, "unknown", req.Method, req.URL.Path, "none",
			models.DecisionDeny, fmt.Sprintf("method %s not allowlisted on path (default deny)", req.Method), http.StatusMethodNotAllowed)
		respondJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowlisted by proxy"})
	})

	// Health check endpoint
	r.Get("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Policy 1: Service Principal Account Operations
	// Base SPN path: ONLY GET is allowed
	r.Get("/api/2.0/accounts/{account_id}/servicePrincipals/{target_spn_id}", s.handleSPNOperation)

	// Federation policies collection: GET, POST, PATCH, DELETE
	r.Route("/api/2.0/accounts/{account_id}/servicePrincipals/{target_spn_id}/federationPolicies", func(r chi.Router) {
		r.Get("/", s.handleSPNOperation)
		r.Post("/", s.handleSPNOperation)
		r.Patch("/", s.handleSPNOperation)
		r.Delete("/", s.handleSPNOperation)

		// Single policy: GET, POST, PATCH, DELETE
		r.Get("/{policy_id}", s.handleSPNOperation)
		r.Post("/{policy_id}", s.handleSPNOperation)
		r.Patch("/{policy_id}", s.handleSPNOperation)
		r.Delete("/{policy_id}", s.handleSPNOperation)
	})

	// Policy 2: Network Connectivity Configuration (NCC) Rules
	// Base NCC path: ONLY GET
	r.Get("/api/2.0/accounts/{account_id}/network-connectivity-configs/{ncc_id}", s.handleNCCOperation)

	// Private endpoint rules collection: GET, POST, PATCH, DELETE
	r.Route("/api/2.0/accounts/{account_id}/network-connectivity-configs/{ncc_id}/private-endpoint-rules", func(r chi.Router) {
		r.Get("/", s.handleNCCOperation)
		r.Post("/", s.handleNCCOperation)
		r.Patch("/", s.handleNCCOperation)
		r.Delete("/", s.handleNCCOperation)

		// Single rule: ONLY GET, PATCH, DELETE (POST on a specific rule ID is not allowed)
		r.Get("/{rule_id}", s.handleNCCOperation)
		r.Patch("/{rule_id}", s.handleNCCOperation)
		r.Delete("/{rule_id}", s.handleNCCOperation)
	})

	return r
}

// authenticateAndCheckWhitelist centralizes:
// 1. Account ID pinning validation (if DATABRICKS_ACCOUNT_ID is set)
// 2. Bearer token extraction
// 3. Workspace URL & ID resolution via shared cached WorkspaceResolver
// 4. Caller identity introspection via SCIM Me (and Workload Identity exchange)
// 5. Calling Service Principal workspace whitelist check
func (s *ProxyServer) authenticateAndCheckWhitelist(
	w http.ResponseWriter,
	r *http.Request,
	reqID, accountID, targetResource, policyName string,
	requireWorkspaceID bool,
) (*models.CallerIdentity, string, bool) {
	// 1. Account ID Pinning Check
	if s.cfg.DatabricksAccountID != "" && s.cfg.DatabricksAccountID != accountID {
		reason := fmt.Sprintf("request account_id '%s' does not match proxy's configured account_id", accountID)
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, reason, http.StatusForbidden)
		respondJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return nil, "", false
	}

	// 2. Required Workspace ID check (for NCC operations)
	workspaceID := r.Header.Get("X-Databricks-Workspace-Id")
	if requireWorkspaceID && workspaceID == "" {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "missing required X-Databricks-Workspace-Id header", http.StatusBadRequest)
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Databricks-Workspace-Id header is required"})
		return nil, "", false
	}

	// 3. Extract Bearer Token
	rawToken, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "missing or malformed Authorization header", http.StatusUnauthorized)
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or malformed Authorization header"})
		return nil, "", false
	}

	// 4. Resolve Workspace URL for caller identity introspection
	workspaceURL := r.Header.Get("X-Databricks-Workspace-Url")
	if workspaceURL == "" && workspaceID != "" {
		resolvedURL, err := s.nccPolicy.WorkspaceResolver().ResolveWorkspaceURL(r.Context(), accountID, workspaceID)
		if err != nil {
			if requireWorkspaceID {
				s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
					models.DecisionDeny, "failed to resolve workspace URL: "+err.Error(), http.StatusBadRequest)
				respondJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to resolve workspace URL"})
				return nil, "", false
			}
		} else {
			workspaceURL = resolvedURL
		}
	}

	if workspaceURL == "" {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "missing workspace context (provide X-Databricks-Workspace-Url or X-Databricks-Workspace-Id)", http.StatusBadRequest)
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Databricks-Workspace-Url header required"})
		return nil, "", false
	}

	// 5. Introspect and validate caller token (supporting Workload Identity & SSRF validation)
	clientID := r.Header.Get("X-Databricks-Client-Id")
	caller, err := s.validator.ValidateCallerWithClientID(r.Context(), rawToken, workspaceURL, clientID)
	if err != nil {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "invalid caller token: "+err.Error(), http.StatusUnauthorized)
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "caller token validation failed: " + err.Error()})
		return nil, "", false
	}

	// 6. Calling Service Principal Workspace Whitelist Check (Defense in Depth)
	if caller.IsServicePrincipal && s.whitelist.IsEnabled() {
		targetWSID := workspaceID
		if targetWSID == "" && workspaceURL != "" {
			if resolvedID, err := s.nccPolicy.WorkspaceResolver().ResolveWorkspaceIDFromURL(r.Context(), accountID, workspaceURL); err == nil {
				targetWSID = resolvedID
			}
		}
		if targetWSID == "" {
			s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, "spn_workspace_whitelist",
				models.DecisionDeny, "X-Databricks-Workspace-Id required to verify calling service principal workspace authorization", http.StatusBadRequest)
			respondJSON(w, http.StatusBadRequest, map[string]string{
				"error": "X-Databricks-Workspace-Id header is required to verify calling service principal workspace authorization",
			})
			return nil, "", false
		}

		if allowed, reason := s.whitelist.CheckSPNWorkspace(caller.PrincipalID, targetWSID); !allowed {
			s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, "spn_workspace_whitelist",
				models.DecisionDeny, reason, http.StatusForbidden)
			respondJSON(w, http.StatusForbidden, map[string]string{"error": reason})
			return nil, "", false
		}
		workspaceID = targetWSID
	}

	return caller, workspaceID, true
}

// handleSPNOperation validates caller and evaluates Policy 1 (roles/servicePrincipal.manager)
func (s *ProxyServer) handleSPNOperation(w http.ResponseWriter, r *http.Request) {
	reqID := GenerateRequestID()
	accountID := chi.URLParam(r, "account_id")
	targetSPNID := chi.URLParam(r, "target_spn_id")
	targetResource := fmt.Sprintf("spn:%s", targetSPNID)
	policyName := "spn_manager"

	caller, _, ok := s.authenticateAndCheckWhitelist(w, r, reqID, accountID, targetResource, policyName, false)
	if !ok {
		return
	}

	// Evaluate Policy 1 (roles/servicePrincipal.manager)
	allowed, reason, err := s.spnPolicy.VerifySPNManager(r.Context(), accountID, targetSPNID, caller)
	if err != nil {
		s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "policy error: "+err.Error(), http.StatusInternalServerError)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy evaluation error"})
		return
	}

	if !allowed {
		s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, reason, http.StatusForbidden)
		respondJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}

	// Authorized: Forward upstream with Account Admin credentials
	s.forwardUpstream(w, r, reqID, caller, targetResource, policyName)
}

// handleNCCOperation validates caller and evaluates Policy 2 (NCC Workspace Admin + 1:1 binding)
func (s *ProxyServer) handleNCCOperation(w http.ResponseWriter, r *http.Request) {
	reqID := GenerateRequestID()
	accountID := chi.URLParam(r, "account_id")
	nccID := chi.URLParam(r, "ncc_id")
	targetResource := fmt.Sprintf("ncc:%s", nccID)
	policyName := "ncc_workspace_admin"

	caller, workspaceID, ok := s.authenticateAndCheckWhitelist(w, r, reqID, accountID, targetResource, policyName, true)
	if !ok {
		return
	}

	// Evaluate Policy 2 (Workspace-to-NCC Binding, 1:1 Isolation, Workspace Admin)
	allowed, reason, err := s.nccPolicy.VerifyNCCWorkspaceAdmin(r.Context(), accountID, nccID, workspaceID, caller)
	if err != nil {
		s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "policy error: "+err.Error(), http.StatusInternalServerError)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy evaluation error: " + err.Error()})
		return
	}

	if !allowed {
		s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, reason, http.StatusForbidden)
		respondJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}

	// Authorized: Forward upstream with Account Admin credentials
	s.forwardUpstream(w, r, reqID, caller, targetResource, policyName)
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
