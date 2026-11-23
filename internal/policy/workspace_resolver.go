package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
)

type cachedWorkspaceList struct {
	workspaces []models.Workspace
	expiresAt  time.Time
}

// WorkspaceResolver provides cached lookups of account workspaces to avoid redundant Account API calls.
type WorkspaceResolver struct {
	cfg          *config.Config
	tokenManager *auth.AdminTokenManager
	httpClient   *http.Client

	mu    sync.RWMutex
	cache map[string]cachedWorkspaceList // key: accountID
}

// NewWorkspaceResolver creates a new cached WorkspaceResolver.
func NewWorkspaceResolver(cfg *config.Config, tokenMgr *auth.AdminTokenManager, httpClient *http.Client) *WorkspaceResolver {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &WorkspaceResolver{
		cfg:          cfg,
		tokenManager: tokenMgr,
		httpClient:   httpClient,
		cache:        make(map[string]cachedWorkspaceList),
	}
}

// ListWorkspaces returns all workspaces in the account, utilizing a short-lived TTL cache.
func (r *WorkspaceResolver) ListWorkspaces(ctx context.Context, accountID string) ([]models.Workspace, error) {
	r.mu.RLock()
	if item, ok := r.cache[accountID]; ok && time.Now().Before(item.expiresAt) {
		ws := item.workspaces
		r.mu.RUnlock()
		return ws, nil
	}
	r.mu.RUnlock()

	adminToken, err := r.tokenManager.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin token: %w", err)
	}

	host := strings.TrimRight(r.cfg.DatabricksAccountsHost, "/")
	allWsURL := fmt.Sprintf("%s/api/2.0/accounts/%s/workspaces", host, accountID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, allWsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create workspaces list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query workspaces list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("workspaces list query returned status %d: %s", resp.StatusCode, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read workspaces list: %w", err)
	}

	workspaces, err := parseWorkspacesList(body)
	if err != nil {
		return nil, err
	}

	ttl := r.cfg.CacheTTL
	if ttl > 0 {
		r.mu.Lock()
		r.cache[accountID] = cachedWorkspaceList{
			workspaces: workspaces,
			expiresAt:  time.Now().Add(ttl),
		}
		r.mu.Unlock()
	}

	return workspaces, nil
}

// GetWorkspace fetches a single workspace by ID (checking the cached list first, then falling back to direct GET).
func (r *WorkspaceResolver) GetWorkspace(ctx context.Context, accountID, workspaceID string) (*models.Workspace, error) {
	cleanID := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(workspaceID), "ws-"), "WS-")

	// Try direct GET endpoint first for authoritative single-workspace lookup, or fall back to cached list
	r.mu.RLock()
	if item, ok := r.cache[accountID]; ok && time.Now().Before(item.expiresAt) {
		for i := range item.workspaces {
			wsIDStr := strconv.FormatInt(item.workspaces[i].WorkspaceID, 10)
			if wsIDStr == cleanID || wsIDStr == workspaceID {
				ws := item.workspaces[i]
				r.mu.RUnlock()
				return &ws, nil
			}
		}
	}
	r.mu.RUnlock()

	adminToken, err := r.tokenManager.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin token: %w", err)
	}

	host := strings.TrimRight(r.cfg.DatabricksAccountsHost, "/")
	wsURL := fmt.Sprintf("%s/api/2.0/accounts/%s/workspaces/%s", host, accountID, workspaceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create workspace request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query workspace: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("workspace query returned status %d: %s", resp.StatusCode, string(b))
	}

	var targetWS models.Workspace
	if err := json.NewDecoder(resp.Body).Decode(&targetWS); err != nil {
		return nil, fmt.Errorf("decode workspace: %w", err)
	}

	return &targetWS, nil
}

// ResolveWorkspaceURL resolves the workspace deployment URL from its workspace ID.
func (r *WorkspaceResolver) ResolveWorkspaceURL(ctx context.Context, accountID, workspaceID string) (string, error) {
	ws, err := r.GetWorkspace(ctx, accountID, workspaceID)
	if err != nil {
		return "", err
	}
	if ws == nil {
		return "", fmt.Errorf("workspace '%s' not found", workspaceID)
	}
	if ws.DeploymentName == "" {
		return "", fmt.Errorf("deployment_name not present on workspace '%s'", workspaceID)
	}
	return resolveWorkspaceDeploymentURL(r.cfg.DatabricksAccountsHost, ws.DeploymentName, ""), nil
}

// ResolveWorkspaceIDFromURL finds the workspace ID matching a workspace deployment URL.
func (r *WorkspaceResolver) ResolveWorkspaceIDFromURL(ctx context.Context, accountID, wsURL string) (string, error) {
	wsList, err := r.ListWorkspaces(ctx, accountID)
	if err != nil {
		return "", err
	}

	lowerWSURL := strings.ToLower(wsURL)
	for _, ws := range wsList {
		if ws.DeploymentName != "" && strings.Contains(lowerWSURL, strings.ToLower(ws.DeploymentName)) {
			return strconv.FormatInt(ws.WorkspaceID, 10), nil
		}
	}

	return "", fmt.Errorf("workspace with URL '%s' not found in account", wsURL)
}
