package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"databricks-account-api-proxy/internal/audit"
	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/models"
	"databricks-account-api-proxy/internal/policy"
	"databricks-account-api-proxy/internal/whitelist"
)

// Hop-by-hop headers to strip
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// ProxyServer coordinates authentication, policy verification, audit logging, and forwarding.
type ProxyServer struct {
	cfg          *config.Config
	tokenManager *auth.AdminTokenManager
	validator    *auth.CallerValidator
	spnPolicy    *policy.SPNManagerPolicy
	nccPolicy    *policy.NCCWorkspaceAdminPolicy
	whitelist    *whitelist.Whitelist
	auditLogger  *audit.Logger
	httpClient   *http.Client
}

// NewProxyServer creates a new configured ProxyServer.
func NewProxyServer(
	cfg *config.Config,
	tokenMgr *auth.AdminTokenManager,
	validator *auth.CallerValidator,
	spnPolicy *policy.SPNManagerPolicy,
	nccPolicy *policy.NCCWorkspaceAdminPolicy,
	wl *whitelist.Whitelist,
	auditLogger *audit.Logger,
	httpClient *http.Client,
) *ProxyServer {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	if wl == nil {
		wl = whitelist.New()
	}
	return &ProxyServer{
		cfg:          cfg,
		tokenManager: tokenMgr,
		validator:    validator,
		spnPolicy:    spnPolicy,
		nccPolicy:    nccPolicy,
		whitelist:    wl,
		auditLogger:  auditLogger,
		httpClient:   httpClient,
	}
}

// forwardUpstream forwards the request to the Databricks Accounts API using the privileged admin token.
func (s *ProxyServer) forwardUpstream(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	caller *models.CallerIdentity,
	targetResource, policyName string,
) {
	ctx := r.Context()
	adminToken, err := s.tokenManager.GetToken(ctx)
	if err != nil {
		s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "failed to get admin token: "+err.Error(), http.StatusInternalServerError)
		http.Error(w, `{"error":"internal authentication error"}`, http.StatusInternalServerError)
		return
	}

	targetURL := fmt.Sprintf("%s%s", strings.TrimRight(s.cfg.DatabricksAccountsHost, "/"), r.URL.RequestURI())
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionDeny, "failed to create upstream request: "+err.Error(), http.StatusInternalServerError)
		http.Error(w, `{"error":"internal request creation error"}`, http.StatusInternalServerError)
		return
	}

	// Copy and sanitize headers
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		// Strip sensitive and hop-by-hop headers
		if lowerKey == "authorization" || lowerKey == "host" || hopByHopHeaders[lowerKey] {
			continue
		}
		// Strip caller-proxy specific headers before upstream forwarding
		if lowerKey == "x-databricks-workspace-url" || lowerKey == "x-databricks-workspace-id" || lowerKey == "x-databricks-client-id" {
			continue
		}
		for _, v := range values {
			upstreamReq.Header.Add(key, v)
		}
	}

	// Inject privileged Account Admin token
	upstreamReq.Header.Set("Authorization", "Bearer "+adminToken)

	// Execute upstream call
	resp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
			models.DecisionAllow, "upstream network error: "+err.Error(), http.StatusBadGateway)
		http.Error(w, `{"error":"upstream gateway error"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward response headers (filter hop-by-hop)
	for key, values := range resp.Header {
		if hopByHopHeaders[strings.ToLower(key)] {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body
	_, _ = io.Copy(w, resp.Body)

	// Record audit entry
	s.auditLogger.Record(reqID, caller, targetResource, r.Method, r.URL.Path, policyName,
		models.DecisionAllow, "", resp.StatusCode)
}

// GenerateRequestID creates a random request UUID / hex string
func GenerateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
