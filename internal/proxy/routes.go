package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"route not allowlisted by proxy"}`))
	})

	// Default Deny for non-allowlisted HTTP methods on known paths
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		reqID := GenerateRequestID()
		s.auditLogger.Record(reqID, nil, "unknown", req.Method, req.URL.Path, "none",
			models.DecisionDeny, fmt.Sprintf("method %s not allowlisted on path (default deny)", req.Method), http.StatusMethodNotAllowed)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"method not allowlisted by proxy"}`))
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

// handleSPNOperation validates caller and evaluates Policy 1 (roles/servicePrincipal.manager)
func (s *ProxyServer) handleSPNOperation(w http.ResponseWriter, r *http.Request) {
	reqID := GenerateRequestID()
	accountID := chi.URLParam(r, "account_id")
	targetSPNID := chi.URLParam(r, "target_spn_id")
	targetResource := fmt.Sprintf("spn:%s", targetSPNID)
	policyName := "spn_manager"

	// 1. Extract Bearer Token
	rawToken, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "missing or malformed Authorization header", http.StatusUnauthorized)
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or malformed Authorization header"})
		return
	}

	// 2. Resolve Workspace context for identity introspection
	workspaceURL := r.Header.Get("X-Databricks-Workspace-Url")
	if workspaceURL == "" {
		// If workspace ID is provided instead, resolve workspace deployment URL
		wsID := r.Header.Get("X-Databricks-Workspace-Id")
		if wsID != "" {
			resolvedURL, err := s.resolveWorkspaceURL(r.Context(), accountID, wsID)
			if err == nil {
				workspaceURL = resolvedURL
			}
		}
	}

	if workspaceURL == "" {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "missing workspace context (provide X-Databricks-Workspace-Url or X-Databricks-Workspace-Id)", http.StatusBadRequest)
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Databricks-Workspace-Url header required"})
		return
	}

	// 3. Introspect and validate caller token (supporting Workload Identity)
	clientID := r.Header.Get("X-Databricks-Client-Id")
	caller, err := s.validator.ValidateCallerWithClientID(r.Context(), rawToken, workspaceURL, clientID)
	if err != nil {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "invalid caller token: "+err.Error(), http.StatusUnauthorized)
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "caller token validation failed: " + err.Error()})
		return
	}

	// 4. Calling Service Principal Workspace Whitelist Check (Defense in Depth)
	if caller.IsServicePrincipal && s.whitelist.IsEnabled() {
		targetWSID := r.Header.Get("X-Databricks-Workspace-Id")
		if targetWSID == "" && workspaceURL != "" {
			if resolvedID, err := s.resolveWorkspaceIDFromURL(r.Context(), accountID, workspaceURL); err == nil {
				targetWSID = resolvedID
			}
		}
		if targetWSID == "" {
			s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, "spn_workspace_whitelist",
				models.DecisionDeny, "X-Databricks-Workspace-Id required to verify calling service principal workspace authorization", http.StatusBadRequest)
			respondJSON(w, http.StatusBadRequest, map[string]string{
				"error": "X-Databricks-Workspace-Id header is required to verify calling service principal workspace authorization",
			})
			return
		}

		if allowed, reason := s.whitelist.CheckSPNWorkspace(caller.PrincipalID, targetWSID); !allowed {
			s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, "spn_workspace_whitelist",
				models.DecisionDeny, reason, http.StatusForbidden)
			respondJSON(w, http.StatusForbidden, map[string]string{"error": reason})
			return
		}
	}

	// 5. Evaluate Policy 1 (roles/servicePrincipal.manager)
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

	// 6. Authorized: Forward upstream with Account Admin credentials
	s.forwardUpstream(w, r, reqID, caller, targetResource, policyName)
}

// handleNCCOperation validates caller and evaluates Policy 2 (NCC Workspace Admin + 1:1 binding)
func (s *ProxyServer) handleNCCOperation(w http.ResponseWriter, r *http.Request) {
	reqID := GenerateRequestID()
	accountID := chi.URLParam(r, "account_id")
	nccID := chi.URLParam(r, "ncc_id")
	targetResource := fmt.Sprintf("ncc:%s", nccID)
	policyName := "ncc_workspace_admin"

	// 1. Required Header: X-Databricks-Workspace-Id
	workspaceID := r.Header.Get("X-Databricks-Workspace-Id")
	if workspaceID == "" {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "missing required X-Databricks-Workspace-Id header", http.StatusBadRequest)
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Databricks-Workspace-Id header is required"})
		return
	}

	// 2. Extract Bearer Token
	rawToken, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "missing or malformed Authorization header", http.StatusUnauthorized)
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or malformed Authorization header"})
		return
	}

	// 3. Resolve Workspace URL for caller validation
	workspaceURL := r.Header.Get("X-Databricks-Workspace-Url")
	if workspaceURL == "" {
		resolvedURL, err := s.resolveWorkspaceURL(r.Context(), accountID, workspaceID)
		if err != nil {
			s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
				models.DecisionDeny, "failed to resolve workspace URL: "+err.Error(), http.StatusBadRequest)
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to resolve workspace URL"})
			return
		}
		workspaceURL = resolvedURL
	}

	// 4. Introspect and validate caller token (supporting Workload Identity)
	clientID := r.Header.Get("X-Databricks-Client-Id")
	caller, err := s.validator.ValidateCallerWithClientID(r.Context(), rawToken, workspaceURL, clientID)
	if err != nil {
		s.auditLogger.Record(reqID, nil, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "invalid caller token: "+err.Error(), http.StatusUnauthorized)
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "caller token validation failed: " + err.Error()})
		return
	}

	// 5. Calling Service Principal Workspace Whitelist Check (Defense in Depth)
	if caller.IsServicePrincipal && s.whitelist.IsEnabled() {
		if allowed, reason := s.whitelist.CheckSPNWorkspace(caller.PrincipalID, workspaceID); !allowed {
			s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, "spn_workspace_whitelist",
				models.DecisionDeny, reason, http.StatusForbidden)
			respondJSON(w, http.StatusForbidden, map[string]string{"error": reason})
			return
		}
	}

	// 6. Evaluate Policy 2 (Workspace-to-NCC Binding, 1:1 Isolation, Workspace Admin)
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

	// 7. Authorized: Forward upstream with Account Admin credentials
	s.forwardUpstream(w, r, reqID, caller, targetResource, policyName)
}

// resolveWorkspaceURL fetches workspace details to determine the deployment URL
func (s *ProxyServer) resolveWorkspaceURL(ctx context.Context, accountID, workspaceID string) (string, error) {
	adminToken, err := s.tokenManager.GetToken(ctx)
	if err != nil {
		return "", fmt.Errorf("admin token: %w", err)
	}

	host := strings.TrimRight(s.cfg.DatabricksAccountsHost, "/")
	wsURL := fmt.Sprintf("%s/api/2.0/accounts/%s/workspaces/%s", host, accountID, workspaceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("workspace query returned %d: %s", resp.StatusCode, string(b))
	}

	var ws models.Workspace
	if err := json.NewDecoder(resp.Body).Decode(&ws); err != nil {
		return "", err
	}

	if ws.DeploymentName != "" {
		lowerHost := strings.ToLower(s.cfg.DatabricksAccountsHost)
		if strings.Contains(lowerHost, "azuredatabricks.net") {
			return fmt.Sprintf("https://%s.azuredatabricks.net", ws.DeploymentName), nil
		}
		if strings.Contains(lowerHost, "gcp.databricks.com") {
			return fmt.Sprintf("https://%s.gcp.databricks.com", ws.DeploymentName), nil
		}
		return fmt.Sprintf("https://%s.cloud.databricks.com", ws.DeploymentName), nil
	}

	return "", fmt.Errorf("deployment_name not present on workspace %s", workspaceID)
}

// resolveWorkspaceIDFromURL extracts deployment name from workspace URL and finds its workspace ID
func (s *ProxyServer) resolveWorkspaceIDFromURL(ctx context.Context, accountID, wsURL string) (string, error) {
	adminToken, err := s.tokenManager.GetToken(ctx)
	if err != nil {
		return "", fmt.Errorf("admin token: %w", err)
	}

	host := strings.TrimRight(s.cfg.DatabricksAccountsHost, "/")
	allWsURL := fmt.Sprintf("%s/api/2.0/accounts/%s/workspaces", host, accountID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, allWsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("workspaces query returned %d: %s", resp.StatusCode, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var wsList []models.Workspace
	if err := json.Unmarshal(body, &wsList); err != nil {
		var wrapped struct {
			Workspaces []models.Workspace `json:"workspaces"`
		}
		if err := json.Unmarshal(body, &wrapped); err != nil {
			return "", err
		}
		wsList = wrapped.Workspaces
	}

	lowerWSURL := strings.ToLower(wsURL)
	for _, ws := range wsList {
		if ws.DeploymentName != "" && strings.Contains(lowerWSURL, strings.ToLower(ws.DeploymentName)) {
			return strconv.FormatInt(ws.WorkspaceID, 10), nil
		}
	}

	return "", fmt.Errorf("workspace with URL %s not found in account", wsURL)
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
