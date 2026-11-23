package models

import "time"

// AuditDecision represents the outcome of policy evaluation
type AuditDecision string

const (
	DecisionAllow AuditDecision = "ALLOW"
	DecisionDeny  AuditDecision = "DENY"
)

// AuditLogEntry is the structured audit record for every request
type AuditLogEntry struct {
	Timestamp          time.Time      `json:"timestamp"`
	RequestID          string         `json:"request_id"`
	CallerIdentity     CallerSummary  `json:"caller_identity"`
	TargetResource     string         `json:"target_resource"`
	HTTPMethod         string         `json:"http_method"`
	Path               string         `json:"path"`
	PolicyEvaluated    string         `json:"policy_evaluated"`
	Decision           AuditDecision  `json:"decision"`
	DenialReason       string         `json:"denial_reason,omitempty"`
	UpstreamStatusCode int            `json:"upstream_status_code,omitempty"`
}

// CallerSummary is a safe, sanitized summary of the caller for audit logs (no tokens!)
type CallerSummary struct {
	PrincipalID        string   `json:"principal_id,omitempty"`
	NumericID          string   `json:"numeric_id,omitempty"`
	Email              string   `json:"email,omitempty"`
	Groups             []string `json:"groups,omitempty"`
	IsServicePrincipal bool     `json:"is_service_principal"`
}
