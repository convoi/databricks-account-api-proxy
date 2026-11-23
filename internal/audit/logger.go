package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"databricks-account-api-proxy/internal/models"
)

// Logger writes structured audit log entries in JSON format.
type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

// NewLogger creates an audit logger writing to the specified writer (or os.Stdout if nil).
func NewLogger(out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{out: out}
}

// Log writes an audit log entry.
func (l *Logger) Log(entry models.AuditLogEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(data, '\n'))
}

// Record allows easy construction and logging of an audit entry.
func (l *Logger) Record(
	reqID string,
	caller *models.CallerIdentity,
	targetResource, method, path, policy string,
	decision models.AuditDecision,
	denialReason string,
	upstreamStatusCode int,
) {
	summary := models.CallerSummary{}
	if caller != nil {
		summary = models.CallerSummary{
			PrincipalID:        caller.PrincipalID,
			NumericID:          caller.NumericID,
			Email:              caller.Email,
			Groups:             caller.Groups,
			IsServicePrincipal: caller.IsServicePrincipal,
		}
	}

	entry := models.AuditLogEntry{
		Timestamp:          time.Now().UTC(),
		RequestID:          reqID,
		CallerIdentity:     summary,
		TargetResource:     targetResource,
		HTTPMethod:         method,
		Path:               path,
		PolicyEvaluated:    policy,
		Decision:           decision,
		DenialReason:       denialReason,
		UpstreamStatusCode: upstreamStatusCode,
	}

	l.Log(entry)
}
