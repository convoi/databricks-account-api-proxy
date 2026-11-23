package models

// CallerIdentity encapsulates the verified identity extracted from the caller's OAuth token.
type CallerIdentity struct {
	PrincipalID        string   `json:"principal_id"`         // Application ID / UUID for SPNs, or email/ID for users
	NumericID          string   `json:"numeric_id"`           // Databricks internal numeric/string ID
	Email              string   `json:"email,omitempty"`      // User email if user
	DisplayName        string   `json:"display_name"`         // Display name
	Groups             []string `json:"groups"`               // List of group names the caller belongs to
	GroupIDs           []string `json:"group_ids,omitempty"`  // List of group IDs
	IsServicePrincipal bool     `json:"is_service_principal"` // True if SPN, false if user
	WorkspaceURL       string   `json:"workspace_url"`        // The workspace URL used to verify caller
}

// HasGroup checks if the caller is a member of the given group name (case-insensitive).
func (c *CallerIdentity) HasGroup(groupName string) bool {
	for _, g := range c.Groups {
		if g == groupName {
			return true
		}
	}
	return false
}
