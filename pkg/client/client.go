package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a Go client for interacting with Databricks Account APIs via the Scoped Proxy.
type Client struct {
	ProxyURL     string
	AccountID    string
	CallerToken  string
	WorkspaceURL string
	WorkspaceID  string
	HTTPClient   *http.Client
}

// ClientConfig holds initialization parameters for the client.
type ClientConfig struct {
	ProxyURL     string
	AccountID    string
	CallerToken  string
	WorkspaceURL string
	WorkspaceID  string
	HTTPClient   *http.Client
}

// NewClient initializes a new proxy client.
func NewClient(cfg ClientConfig) *Client {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		ProxyURL:     strings.TrimRight(cfg.ProxyURL, "/"),
		AccountID:    cfg.AccountID,
		CallerToken:  cfg.CallerToken,
		WorkspaceURL: cfg.WorkspaceURL,
		WorkspaceID:  cfg.WorkspaceID,
		HTTPClient:   hc,
	}
}

// FederationPolicy represents a Databricks SPN Federation Policy
type FederationPolicy struct {
	PolicyID    string   `json:"policy_id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Audiences   []string `json:"audiences,omitempty"`
}

// PrivateEndpointRule represents an NCC private endpoint rule
type PrivateEndpointRule struct {
	RuleID               string `json:"rule_id,omitempty"`
	ResourceID           string `json:"resource_id,omitempty"`
	GroupID              string `json:"group_id,omitempty"`
	EndpointName         string `json:"endpoint_name,omitempty"`
	ConnectionState      string `json:"connection_state,omitempty"`
	Deactivated          bool   `json:"deactivated,omitempty"`
	CreationTime         int64  `json:"creation_time,omitempty"`
	UpdatedTime          int64  `json:"updated_time,omitempty"`
	NetworkConnectivity  string `json:"network_connectivity_config_id,omitempty"`
}

// ServicePrincipal represents basic SPN info returned by GET /servicePrincipals/{id}
type ServicePrincipal struct {
	ID            string `json:"id"`
	ApplicationID string `json:"application_id"`
	DisplayName   string `json:"display_name"`
	Active        bool   `json:"active"`
}

// --- SPN Operations (Policy 1) ---

func (c *Client) GetServicePrincipal(ctx context.Context, targetSPNID string) (*ServicePrincipal, error) {
	path := fmt.Sprintf("/api/2.0/accounts/%s/servicePrincipals/%s", c.AccountID, targetSPNID)
	var spn ServicePrincipal
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &spn); err != nil {
		return nil, err
	}
	return &spn, nil
}

func (c *Client) GetFederationPolicy(ctx context.Context, targetSPNID, policyID string) (*FederationPolicy, error) {
	path := fmt.Sprintf("/api/2.0/accounts/%s/servicePrincipals/%s/federationPolicies/%s", c.AccountID, targetSPNID, policyID)
	var pol FederationPolicy
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &pol); err != nil {
		return nil, err
	}
	return &pol, nil
}

func (c *Client) CreateFederationPolicy(ctx context.Context, targetSPNID string, policy *FederationPolicy) (*FederationPolicy, error) {
	path := fmt.Sprintf("/api/2.0/accounts/%s/servicePrincipals/%s/federationPolicies", c.AccountID, targetSPNID)
	var created FederationPolicy
	if err := c.doRequest(ctx, http.MethodPost, path, policy, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) UpdateFederationPolicy(ctx context.Context, targetSPNID, policyID string, policy *FederationPolicy) (*FederationPolicy, error) {
	path := fmt.Sprintf("/api/2.0/accounts/%s/servicePrincipals/%s/federationPolicies/%s", c.AccountID, targetSPNID, policyID)
	var updated FederationPolicy
	if err := c.doRequest(ctx, http.MethodPatch, path, policy, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func (c *Client) DeleteFederationPolicy(ctx context.Context, targetSPNID, policyID string) error {
	path := fmt.Sprintf("/api/2.0/accounts/%s/servicePrincipals/%s/federationPolicies/%s", c.AccountID, targetSPNID, policyID)
	return c.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// --- NCC Operations (Policy 2) ---

func (c *Client) GetPrivateEndpointRule(ctx context.Context, nccID, ruleID string) (*PrivateEndpointRule, error) {
	path := fmt.Sprintf("/api/2.0/accounts/%s/network-connectivity-configs/%s/private-endpoint-rules/%s", c.AccountID, nccID, ruleID)
	var rule PrivateEndpointRule
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

func (c *Client) CreatePrivateEndpointRule(ctx context.Context, nccID string, rule *PrivateEndpointRule) (*PrivateEndpointRule, error) {
	path := fmt.Sprintf("/api/2.0/accounts/%s/network-connectivity-configs/%s/private-endpoint-rules", c.AccountID, nccID)
	var created PrivateEndpointRule
	if err := c.doRequest(ctx, http.MethodPost, path, rule, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) UpdatePrivateEndpointRule(ctx context.Context, nccID, ruleID string, rule *PrivateEndpointRule) (*PrivateEndpointRule, error) {
	path := fmt.Sprintf("/api/2.0/accounts/%s/network-connectivity-configs/%s/private-endpoint-rules/%s", c.AccountID, nccID, ruleID)
	var updated PrivateEndpointRule
	if err := c.doRequest(ctx, http.MethodPatch, path, rule, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func (c *Client) DeletePrivateEndpointRule(ctx context.Context, nccID, ruleID string) error {
	path := fmt.Sprintf("/api/2.0/accounts/%s/network-connectivity-configs/%s/private-endpoint-rules/%s", c.AccountID, nccID, ruleID)
	return c.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// ErrNotFound indicates the target upstream resource returned HTTP 404.
type ErrNotFound struct {
	Path    string
	Message string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("resource not found (%s): %s", e.Path, e.Message)
}

// IsNotFound checks if an error is an *ErrNotFound.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*ErrNotFound)
	return ok
}

func (c *Client) doRequest(ctx context.Context, method, path string, inPayload any, outResult any) error {
	var bodyReader io.Reader
	if inPayload != nil {
		data, err := json.Marshal(inPayload)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	reqURL := fmt.Sprintf("%s%s", c.ProxyURL, path)
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.CallerToken)
	req.Header.Set("Accept", "application/json")
	if inPayload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.WorkspaceURL != "" {
		req.Header.Set("X-Databricks-Workspace-Url", c.WorkspaceURL)
	}
	if c.WorkspaceID != "" {
		req.Header.Set("X-Databricks-Workspace-Id", c.WorkspaceID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return &ErrNotFound{Path: path, Message: string(bodyBytes)}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("api error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	if outResult != nil && len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, outResult); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

// ExchangeWorkloadIdentityToken exchanges an external OIDC token for a Databricks OAuth access token.
// oidcEndpoint is typically https://<workspace_url>/oidc/v1/token or https://<accounts_host>/oidc/v1/token.
func ExchangeWorkloadIdentityToken(ctx context.Context, httpClient *http.Client, oidcEndpoint, clientID, oidcToken string) (string, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	formData := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"all-apis"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {oidcToken},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("workload identity exchange returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("workload identity exchange returned empty access_token")
	}

	return tokenResp.AccessToken, nil
}
