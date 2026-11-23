package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
)

var (
	ErrMissingAuthHeader    = errors.New("missing or malformed Authorization header")
	ErrMissingWorkspace     = errors.New("missing workspace context (specify X-Databricks-Workspace-Url or X-Databricks-Workspace-Id)")
	ErrInvalidWorkspaceHost = errors.New("untrusted workspace URL host (must be a valid Databricks domain)")
	ErrInvalidToken         = errors.New("caller token validation failed")
)

const maxCacheEntries = 2048

type cachedIdentity struct {
	identity  *models.CallerIdentity
	expiresAt time.Time
}

// CallerValidator verifies caller OAuth tokens against Databricks SCIM endpoints.
type CallerValidator struct {
	cfg        *config.Config
	httpClient *http.Client
	cacheMu    sync.RWMutex
	cache      map[string]cachedIdentity
}

// NewCallerValidator creates a new caller validator.
func NewCallerValidator(cfg *config.Config, httpClient *http.Client) *CallerValidator {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &CallerValidator{
		cfg:        cfg,
		httpClient: httpClient,
		cache:      make(map[string]cachedIdentity),
	}
}

// ExtractBearerToken parses the Bearer token from the Authorization header.
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingAuthHeader
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrMissingAuthHeader
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrMissingAuthHeader
	}
	return token, nil
}

// ValidateWorkspaceURL ensures the workspace URL points to a trusted Databricks domain (SSRF protection).
func (v *CallerValidator) ValidateWorkspaceURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(strings.TrimRight(rawURL, "/"))
	if rawURL == "" {
		return "", ErrMissingWorkspace
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("%w: malformed URL", ErrInvalidWorkspaceHost)
	}

	host := strings.ToLower(parsed.Hostname())

	// Trusted production Databricks domains
	if strings.HasSuffix(host, ".cloud.databricks.com") ||
		strings.HasSuffix(host, ".azuredatabricks.net") ||
		strings.HasSuffix(host, ".gcp.databricks.com") ||
		strings.HasSuffix(host, ".databricks.azure.cn") {
		if parsed.Scheme != "https" {
			return "", fmt.Errorf("%w: HTTPS is required for Databricks workspace URLs", ErrInvalidWorkspaceHost)
		}
		return fmt.Sprintf("https://%s", parsed.Host), nil
	}

	// Allow localhost / 127.0.0.1 only when DatabricksAccountsHost itself is configured for local testing
	if v.cfg != nil {
		if accParsed, err := url.Parse(v.cfg.DatabricksAccountsHost); err == nil {
			accHost := strings.ToLower(accParsed.Hostname())
			if (accHost == "127.0.0.1" || accHost == "localhost") && (host == "127.0.0.1" || host == "localhost") {
				return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host), nil
			}
		}
	}

	return "", fmt.Errorf("%w: '%s'", ErrInvalidWorkspaceHost, host)
}

// ValidateCaller validates the caller's token against the target workspace SCIM endpoint.
func (v *CallerValidator) ValidateCaller(ctx context.Context, rawToken, workspaceURL string) (*models.CallerIdentity, error) {
	return v.ValidateCallerWithClientID(ctx, rawToken, workspaceURL, "")
}

// ValidateCallerWithClientID validates the caller's token, attempting Workload Identity exchange if clientID is supplied.
func (v *CallerValidator) ValidateCallerWithClientID(ctx context.Context, rawToken, workspaceURL, clientID string) (*models.CallerIdentity, error) {
	if rawToken == "" {
		return nil, ErrMissingAuthHeader
	}

	sanitizedWorkspaceURL, err := v.ValidateWorkspaceURL(workspaceURL)
	if err != nil {
		return nil, err
	}
	workspaceURL = sanitizedWorkspaceURL

	// Check cache using SHA-256 of token + workspaceURL + clientID
	cacheKey := tokenHash(rawToken, workspaceURL+":"+clientID)
	v.cacheMu.RLock()
	if item, found := v.cache[cacheKey]; found && time.Now().Before(item.expiresAt) {
		v.cacheMu.RUnlock()
		return item.identity, nil
	}
	v.cacheMu.RUnlock()

	// Query /api/2.0/preview/scim/v2/Me on the workspace
	scimURL := fmt.Sprintf("%s/api/2.0/preview/scim/v2/Me", workspaceURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scimURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create SCIM Me request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Accept", "application/scim+json, application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SCIM Me request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read SCIM response body: %w", err)
	}

	// If SCIM returns 401 Unauthorized, check if rawToken is an external Workload Identity JWT assertion
	if resp.StatusCode == http.StatusUnauthorized && clientID != "" && strings.Count(rawToken, ".") == 2 {
		tokenEndpoint := fmt.Sprintf("%s/oidc/v1/token", workspaceURL)
		formData := url.Values{
			"grant_type":            {"client_credentials"},
			"scope":                 {"all-apis"},
			"client_id":             {clientID},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {rawToken},
		}

		exchReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(formData.Encode()))
		if err == nil {
			exchReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if exchResp, err := v.httpClient.Do(exchReq); err == nil {
				defer exchResp.Body.Close()
				if exchResp.StatusCode == http.StatusOK {
					var tokResp struct {
						AccessToken string `json:"access_token"`
					}
					if err := json.NewDecoder(exchResp.Body).Decode(&tokResp); err == nil && tokResp.AccessToken != "" {
						retryReq, err := http.NewRequestWithContext(ctx, http.MethodGet, scimURL, nil)
						if err == nil {
							retryReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
							retryReq.Header.Set("Accept", "application/scim+json, application/json")
							if retryResp, err := v.httpClient.Do(retryReq); err == nil {
								defer retryResp.Body.Close()
								if retryResp.StatusCode == http.StatusOK {
									resp = retryResp
									bodyBytes, _ = io.ReadAll(retryResp.Body)
								}
							}
						}
					}
				}
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: upstream SCIM Me returned %d: %s", ErrInvalidToken, resp.StatusCode, string(bodyBytes))
	}

	var me models.SCIMMeResponse
	if err := json.Unmarshal(bodyBytes, &me); err != nil {
		return nil, fmt.Errorf("parse SCIM Me response: %w", err)
	}

	identity := &models.CallerIdentity{
		NumericID:    me.ID,
		DisplayName:  me.DisplayName,
		WorkspaceURL: workspaceURL,
	}

	// Extract groups
	var groupNames []string
	var groupIDs []string
	for _, g := range me.Groups {
		if g.Display != "" {
			groupNames = append(groupNames, g.Display)
		} else if g.Value != "" {
			groupNames = append(groupNames, g.Value)
		}
		if g.Value != "" {
			groupIDs = append(groupIDs, g.Value)
		}
	}
	identity.Groups = groupNames
	identity.GroupIDs = groupIDs

	// Determine principal ID & type
	if me.ApplicationID != "" {
		identity.PrincipalID = me.ApplicationID
		identity.IsServicePrincipal = true
	} else {
		// User principal
		identity.PrincipalID = me.UserName
		if strings.Contains(me.UserName, "@") {
			identity.Email = me.UserName
		}
		for _, email := range me.Emails {
			if email.Primary || identity.Email == "" {
				identity.Email = email.Value
			}
		}
		identity.IsServicePrincipal = false
	}

	// Cache the verified identity for the configured TTL with bounded eviction
	ttl := v.cfg.CacheTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	now := time.Now()
	v.cacheMu.Lock()
	if len(v.cache) >= maxCacheEntries {
		for k, entry := range v.cache {
			if now.After(entry.expiresAt) {
				delete(v.cache, k)
			}
		}
		// If still full after pruning expired items, clear half the map
		if len(v.cache) >= maxCacheEntries {
			count := 0
			for k := range v.cache {
				delete(v.cache, k)
				count++
				if count >= maxCacheEntries/2 {
					break
				}
			}
		}
	}
	v.cache[cacheKey] = cachedIdentity{
		identity:  identity,
		expiresAt: now.Add(ttl),
	}
	v.cacheMu.Unlock()

	return identity, nil
}

func tokenHash(token, contextStr string) string {
	h := sha256.New()
	h.Write([]byte(token))
	h.Write([]byte("|"))
	h.Write([]byte(contextStr))
	return hex.EncodeToString(h.Sum(nil))
}
