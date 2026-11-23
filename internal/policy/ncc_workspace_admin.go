package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
)

// NCCWorkspaceAdminPolicy evaluates the 3-step NCC authorization rule:
// 1. Workspace-to-NCC Binding
// 2. 1:1 Isolation Check (Blast Radius Prevention across all workspaces)
// 3. Workspace Admin Verification (member of 'admins' group)
type NCCWorkspaceAdminPolicy struct {
	cfg          *config.Config
	tokenManager *auth.AdminTokenManager
	httpClient   *http.Client
}

// NewNCCWorkspaceAdminPolicy creates a new NCC policy evaluator.
func NewNCCWorkspaceAdminPolicy(cfg *config.Config, tokenMgr *auth.AdminTokenManager, httpClient *http.Client) *NCCWorkspaceAdminPolicy {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &NCCWorkspaceAdminPolicy{
		cfg:          cfg,
		tokenManager: tokenMgr,
		httpClient:   httpClient,
	}
}

// VerifyNCCWorkspaceAdmin runs all 3 checks. Returns (allowed, denialReason, error).
func (p *NCCWorkspaceAdminPolicy) VerifyNCCWorkspaceAdmin(
	ctx context.Context,
	accountID, nccID, workspaceID string,
	caller *models.CallerIdentity,
) (bool, string, error) {
	if caller == nil {
		return false, "caller identity is missing", nil
	}
	if accountID == "" {
		return false, "account_id is required", nil
	}
	if nccID == "" {
		return false, "ncc_id is required", nil
	}
	if workspaceID == "" {
		return false, "X-Databricks-Workspace-Id header is required", nil
	}

	adminToken, err := p.tokenManager.GetToken(ctx)
	if err != nil {
		return false, "failed to obtain account admin token", fmt.Errorf("admin token: %w", err)
	}

	host := strings.TrimRight(p.cfg.DatabricksAccountsHost, "/")

	// --- Check 1: Workspace-to-NCC Binding ---
	wsURL := fmt.Sprintf("%s/api/2.0/accounts/%s/workspaces/%s", host, accountID, workspaceID)
	req1, err := http.NewRequestWithContext(ctx, http.MethodGet, wsURL, nil)
	if err != nil {
		return false, "failed to create workspace query request", fmt.Errorf("new request: %w", err)
	}
	req1.Header.Set("Authorization", "Bearer "+adminToken)
	req1.Header.Set("Accept", "application/json")

	resp1, err := p.httpClient.Do(req1)
	if err != nil {
		return false, "failed to query workspace details", fmt.Errorf("do request: %w", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode == http.StatusNotFound {
		return false, fmt.Sprintf("workspace '%s' not found", workspaceID), nil
	}
	if resp1.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp1.Body)
		return false, fmt.Sprintf("workspace query returned status %d", resp1.StatusCode),
			fmt.Errorf("status %d: %s", resp1.StatusCode, string(b))
	}

	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		return false, "failed to read workspace response", fmt.Errorf("read: %w", err)
	}

	var targetWS models.Workspace
	if err := json.Unmarshal(body1, &targetWS); err != nil {
		return false, "failed to parse workspace response", fmt.Errorf("unmarshal: %w", err)
	}

	if targetWS.NetworkConnectivityConfigID == "" || targetWS.NetworkConnectivityConfigID != nccID {
		return false, fmt.Sprintf("workspace '%s' is not bound to NCC '%s' (bound to '%s')",
			workspaceID, nccID, targetWS.NetworkConnectivityConfigID), nil
	}

	// --- Check 2: 1:1 Isolation Check (Blast Radius Prevention) ---
	allWsURL := fmt.Sprintf("%s/api/2.0/accounts/%s/workspaces", host, accountID)
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, allWsURL, nil)
	if err != nil {
		return false, "failed to create all workspaces query request", fmt.Errorf("new request: %w", err)
	}
	req2.Header.Set("Authorization", "Bearer "+adminToken)
	req2.Header.Set("Accept", "application/json")

	resp2, err := p.httpClient.Do(req2)
	if err != nil {
		return false, "failed to query workspaces list", fmt.Errorf("do request: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		return false, fmt.Sprintf("workspaces list query returned status %d", resp2.StatusCode),
			fmt.Errorf("status %d: %s", resp2.StatusCode, string(b))
	}

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return false, "failed to read workspaces list", fmt.Errorf("read: %w", err)
	}

	workspaces, err := parseWorkspacesList(body2)
	if err != nil {
		return false, "failed to parse workspaces list", fmt.Errorf("parse workspaces: %w", err)
	}

	var boundWorkspaces []string
	cleanTargetID := strings.TrimPrefix(workspaceID, "ws-")

	for _, ws := range workspaces {
		if ws.NetworkConnectivityConfigID == nccID {
			wsIDStr := strconv.FormatInt(ws.WorkspaceID, 10)
			boundWorkspaces = append(boundWorkspaces, wsIDStr)
			// Check if another workspace shares this NCC
			if wsIDStr != cleanTargetID && wsIDStr != workspaceID {
				return false, fmt.Sprintf("NCC '%s' is shared across multiple workspaces (found: %s); 1:1 isolation check failed",
					nccID, strings.Join(boundWorkspaces, ", ")), nil
			}
		}
	}

	// --- Check 3: Workspace Admin Verification ---
	// Determine the workspace deployment URL
	deploymentURL := resolveWorkspaceDeploymentURL(p.cfg.DatabricksAccountsHost, targetWS.DeploymentName, caller.WorkspaceURL)

	isAdmin, err := p.verifyCallerIsWorkspaceAdmin(ctx, deploymentURL, adminToken, caller)
	if err != nil {
		return false, "failed to verify workspace admin status", fmt.Errorf("verify admin: %w", err)
	}

	if !isAdmin {
		return false, fmt.Sprintf("caller '%s' is not an admin of workspace '%s' (not in 'admins' group)",
			caller.PrincipalID, workspaceID), nil
	}

	return true, "", nil
}

// verifyCallerIsWorkspaceAdmin verifies whether caller is in the 'admins' group in the workspace.
func (p *NCCWorkspaceAdminPolicy) verifyCallerIsWorkspaceAdmin(
	ctx context.Context,
	workspaceURL, adminToken string,
	caller *models.CallerIdentity,
) (bool, error) {
	// If caller's verified token was already evaluated on this exact workspace and caller has 'admins', accept
	if caller.HasGroup("admins") {
		// Double check if caller was verified on this exact workspace or if we need to query workspace SCIM
		if strings.TrimRight(caller.WorkspaceURL, "/") == strings.TrimRight(workspaceURL, "/") {
			return true, nil
		}
	}

	// Query workspace SCIM API using the admin token
	baseURL := strings.TrimRight(workspaceURL, "/")
	var scimEndpoint string

	if caller.IsServicePrincipal {
		filter := url.QueryEscape(fmt.Sprintf(`applicationId eq "%s"`, caller.PrincipalID))
		scimEndpoint = fmt.Sprintf("%s/api/2.0/preview/scim/v2/ServicePrincipals?filter=%s", baseURL, filter)
	} else {
		filter := url.QueryEscape(fmt.Sprintf(`userName eq "%s"`, caller.PrincipalID))
		scimEndpoint = fmt.Sprintf("%s/api/2.0/preview/scim/v2/Users?filter=%s", baseURL, filter)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scimEndpoint, nil)
	if err != nil {
		return false, fmt.Errorf("create scim search request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Accept", "application/scim+json, application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("do scim search: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("scim query returned status %d: %s", resp.StatusCode, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read scim body: %w", err)
	}

	var searchResp models.SCIMSearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return false, fmt.Errorf("unmarshal scim search: %w", err)
	}

	if len(searchResp.Resources) == 0 {
		return false, nil
	}

	// Check if any returned resource has 'admins' group
	for _, res := range searchResp.Resources {
		for _, g := range res.Groups {
			if strings.EqualFold(g.Display, "admins") || strings.EqualFold(g.Value, "admins") {
				return true, nil
			}
		}
	}

	return false, nil
}

// parseWorkspacesList handles Databricks Account API returning either []Workspace or {"workspaces": []Workspace}
func parseWorkspacesList(data []byte) ([]models.Workspace, error) {
	var directList []models.Workspace
	if err := json.Unmarshal(data, &directList); err == nil {
		return directList, nil
	}

	var wrapped struct {
		Workspaces []models.Workspace `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Workspaces != nil {
		return wrapped.Workspaces, nil
	}

	return nil, fmt.Errorf("unrecognized workspaces JSON format")
}

// resolveWorkspaceDeploymentURL computes the workspace URL from accountsHost and deploymentName
func resolveWorkspaceDeploymentURL(accountsHost, deploymentName, fallbackURL string) string {
	lowerHost := strings.ToLower(accountsHost)
	if strings.Contains(lowerHost, "127.0.0.1") || strings.Contains(lowerHost, "localhost") {
		if fallbackURL != "" {
			return fallbackURL
		}
		return accountsHost
	}

	if deploymentName != "" {
		if strings.Contains(lowerHost, "azuredatabricks.net") {
			return fmt.Sprintf("https://%s.azuredatabricks.net", deploymentName)
		}
		if strings.Contains(lowerHost, "gcp.databricks.com") {
			return fmt.Sprintf("https://%s.gcp.databricks.com", deploymentName)
		}
		return fmt.Sprintf("https://%s.cloud.databricks.com", deploymentName)
	}

	if fallbackURL != "" {
		return fallbackURL
	}

	return accountsHost
}
