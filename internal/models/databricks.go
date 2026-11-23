package models

// SCIMMeResponse represents the response from GET /api/2.0/preview/scim/v2/Me
type SCIMMeResponse struct {
	ID            string      `json:"id"`
	UserName      string      `json:"userName"`
	DisplayName   string      `json:"displayName"`
	ApplicationID string      `json:"applicationId"`
	Active        bool        `json:"active"`
	Groups        []SCIMGroup `json:"groups"`
	Emails        []SCIMEmail `json:"emails"`
	Roles         []SCIMRole  `json:"roles"`
}

type SCIMGroup struct {
	Value   string `json:"value"`
	Display string `json:"display"`
	Ref     string `json:"$ref"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

type SCIMRole struct {
	Value string `json:"value"`
}

// SCIMSearchResponse represents a SCIM v2 ListResponse
type SCIMSearchResponse struct {
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	ItemsPerPage int              `json:"itemsPerPage"`
	Resources    []SCIMMeResponse `json:"Resources"`
}

// AccessControlRuleSet represents the response from:
// GET /api/2.0/preview/accounts/{account_id}/access-control/rule-sets/accounts/{account_id}/servicePrincipals/{target_spn_id}
type AccessControlRuleSet struct {
	Name       string      `json:"name"`
	Etag       string      `json:"etag"`
	GrantRules []GrantRule `json:"grant_rules"`
}

type GrantRule struct {
	Role       string   `json:"role"`
	Principals []string `json:"principals"`
}

// Workspace represents a Databricks workspace object in the Account API
type Workspace struct {
	WorkspaceID                 int64  `json:"workspace_id"`
	WorkspaceName               string `json:"workspace_name"`
	DeploymentName              string `json:"deployment_name"`
	WorkspaceStatus             string `json:"workspace_status"`
	WorkspaceStatusMessage      string `json:"workspace_status_message"`
	NetworkConnectivityConfigID string `json:"network_connectivity_config_id"`
	GcpWorkspaceConfig          any    `json:"gcp_workspace_config,omitempty"`
}

// NCC represents a Network Connectivity Config
type NCC struct {
	NetworkConnectivityConfigID string `json:"network_connectivity_config_id"`
	Name                        string `json:"name"`
	Region                      string `json:"region"`
	AccountID                   string `json:"account_id"`
}
