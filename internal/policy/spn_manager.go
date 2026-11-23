package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
)

const (
	RoleSPNManager = "roles/servicePrincipal.manager"
)

// SPNManagerPolicy evaluates whether a caller has roles/servicePrincipal.manager on a target SPN.
type SPNManagerPolicy struct {
	cfg          *config.Config
	tokenManager *auth.AdminTokenManager
	httpClient   *http.Client
}

// NewSPNManagerPolicy creates an SPN policy evaluator.
func NewSPNManagerPolicy(cfg *config.Config, tokenMgr *auth.AdminTokenManager, httpClient *http.Client) *SPNManagerPolicy {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &SPNManagerPolicy{
		cfg:          cfg,
		tokenManager: tokenMgr,
		httpClient:   httpClient,
	}
}

// VerifySPNManager checks if caller is authorized as a manager for targetSPNID.
// Returns (allowed, denialReason, error).
func (p *SPNManagerPolicy) VerifySPNManager(ctx context.Context, accountID, targetSPNID string, caller *models.CallerIdentity) (bool, string, error) {
	if caller == nil {
		return false, "caller identity is missing", nil
	}
	if accountID == "" {
		return false, "account_id is required", nil
	}
	if targetSPNID == "" {
		return false, "target_spn_id is required", nil
	}

	adminToken, err := p.tokenManager.GetToken(ctx)
	if err != nil {
		return false, "failed to obtain account admin token", fmt.Errorf("admin token: %w", err)
	}

	// GET https://{accounts_host}/api/2.0/preview/accounts/{account_id}/access-control/rule-sets/accounts/{account_id}/servicePrincipals/{target_spn_id}
	host := strings.TrimRight(p.cfg.DatabricksAccountsHost, "/")
	url := fmt.Sprintf("%s/api/2.0/preview/accounts/%s/access-control/rule-sets/accounts/%s/servicePrincipals/%s",
		host, accountID, accountID, targetSPNID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "failed to create rule-sets request", fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, "failed to query access-control rule-sets", fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, fmt.Sprintf("target service principal '%s' or its rule-set not found", targetSPNID), nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Sprintf("upstream rule-sets query failed with status %d", resp.StatusCode),
			fmt.Errorf("upstream status %d: %s", resp.StatusCode, string(body))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "failed to read rule-sets response", fmt.Errorf("read body: %w", err)
	}

	var ruleSet models.AccessControlRuleSet
	if err := json.Unmarshal(bodyBytes, &ruleSet); err != nil {
		return false, "failed to parse rule-sets response", fmt.Errorf("unmarshal: %w", err)
	}

	// Find the rule where role == "roles/servicePrincipal.manager"
	var managerRule *models.GrantRule
	for i := range ruleSet.GrantRules {
		if ruleSet.GrantRules[i].Role == RoleSPNManager {
			managerRule = &ruleSet.GrantRules[i]
			break
		}
	}

	if managerRule == nil {
		return false, fmt.Sprintf("no grant rule found for role '%s' on target SPN", RoleSPNManager), nil
	}

	// Check if caller's principal or groups are in managerRule.Principals
	allowed := checkPrincipalsMatch(managerRule.Principals, caller)
	if !allowed {
		return false, fmt.Sprintf("caller '%s' does not have role '%s' on SPN '%s'", caller.PrincipalID, RoleSPNManager, targetSPNID), nil
	}

	return true, "", nil
}

// checkPrincipalsMatch checks if any direct or group identity matches the grant rule principals
func checkPrincipalsMatch(principals []string, caller *models.CallerIdentity) bool {
	// Construct candidate strings for the caller
	candidates := make(map[string]bool)

	if caller.IsServicePrincipal {
		candidates["servicePrincipals/"+caller.PrincipalID] = true
	} else {
		if caller.Email != "" {
			candidates["users/"+caller.Email] = true
		}
		if caller.PrincipalID != "" {
			candidates["users/"+caller.PrincipalID] = true
		}
	}

	// Group candidates
	for _, group := range caller.Groups {
		candidates["groups/"+group] = true
	}
	for _, gid := range caller.GroupIDs {
		candidates["groups/"+gid] = true
	}

	for _, p := range principals {
		if candidates[p] {
			return true
		}
	}

	return false
}
