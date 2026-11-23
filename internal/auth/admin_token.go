package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"databricks-account-api-proxy/internal/config"
)

// TokenResponse represents the OAuth M2M response from /oidc/v1/token.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// AdminTokenManager manages the lifecycle of the privileged Databricks Account Admin OAuth token.
type AdminTokenManager struct {
	cfg        *config.Config
	httpClient *http.Client
	mu         sync.RWMutex
	token      string
	expiresAt  time.Time
}

// NewAdminTokenManager creates a new token manager.
func NewAdminTokenManager(cfg *config.Config, httpClient *http.Client) *AdminTokenManager {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &AdminTokenManager{
		cfg:        cfg,
		httpClient: httpClient,
	}
}

// GetToken returns a valid OAuth access token, automatically refreshing if needed.
func (m *AdminTokenManager) GetToken(ctx context.Context) (string, error) {
	m.mu.RLock()
	// Refresh if expiring in less than 60 seconds
	if m.token != "" && time.Until(m.expiresAt) > 60*time.Second {
		tok := m.token
		m.mu.RUnlock()
		return tok, nil
	}
	m.mu.RUnlock()

	// Acquire write lock to refresh
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if m.token != "" && time.Until(m.expiresAt) > 60*time.Second {
		return m.token, nil
	}

	newToken, expiresIn, err := m.fetchNewToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch account admin token: %w", err)
	}

	m.token = newToken
	m.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return m.token, nil
}

// fetchNewToken performs OAuth exchange using Workload Identity Federation (RFC 7523) or client credentials.
func (m *AdminTokenManager) fetchNewToken(ctx context.Context) (string, int64, error) {
	tokenURL := fmt.Sprintf("%s/oidc/v1/token", strings.TrimRight(m.cfg.DatabricksAccountsHost, "/"))

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"all-apis"},
		"client_id":  {m.cfg.ProxyClientID},
	}

	var basicAuthSecret string

	// 1. Workload Identity Federation (OIDC Token assertion)
	if m.cfg.ProxyOIDCTokenFile != "" || m.cfg.ProxyOIDCToken != "" {
		oidcToken := m.cfg.ProxyOIDCToken
		if m.cfg.ProxyOIDCTokenFile != "" {
			tokenBytes, err := os.ReadFile(m.cfg.ProxyOIDCTokenFile)
			if err != nil {
				return "", 0, fmt.Errorf("read workload identity token file '%s': %w", m.cfg.ProxyOIDCTokenFile, err)
			}
			oidcToken = strings.TrimSpace(string(tokenBytes))
		}
		if oidcToken == "" {
			return "", 0, fmt.Errorf("workload identity OIDC token is empty")
		}
		formData.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		formData.Set("client_assertion", oidcToken)
	} else if m.cfg.ProxyClientSecret != "" {
		// 2. Standard M2M Client Credentials
		formData.Set("client_secret", m.cfg.ProxyClientSecret)
		basicAuthSecret = m.cfg.ProxyClientSecret
	} else {
		return "", 0, fmt.Errorf("no credentials configured (set PROXY_CLIENT_SECRET or PROXY_OIDC_TOKEN/PROXY_OIDC_TOKEN_FILE)")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuthSecret != "" {
		req.SetBasicAuth(m.cfg.ProxyClientID, basicAuthSecret)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("unmarshal token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("token response contained empty access_token")
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // fallback to 1 hour if not specified
	}

	return tokenResp.AccessToken, expiresIn, nil
}
