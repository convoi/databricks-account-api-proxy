package whitelist

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Whitelist manages allowed workspaces per calling Service Principal.
type Whitelist struct {
	spnWorkspaces map[string]map[string]bool
	enabled       bool
}

// ConfigFile represents the schema of the whitelist configuration file.
// It supports both:
//
// 1) Wrapped:
//
//	spn_workspace_whitelist:
//	  "spn-uuid-1": ["123456", "789012"]
//
// 2) Direct root mapping:
//
//	"spn-uuid-1": ["123456", "789012"]
type ConfigFile struct {
	SPNWorkspaceWhitelist map[string][]string `yaml:"spn_workspace_whitelist" json:"spn_workspace_whitelist"`
}

// New creates an empty Whitelist.
func New() *Whitelist {
	return &Whitelist{
		spnWorkspaces: make(map[string]map[string]bool),
		enabled:       false,
	}
}

// LoadFromFile loads the whitelist configuration from a YAML or JSON file.
func LoadFromFile(filePath string) (*Whitelist, error) {
	wl := New()
	if filePath == "" {
		return wl, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read whitelist config file '%s': %w", filePath, err)
	}

	if err := wl.parseData(data); err != nil {
		return nil, fmt.Errorf("parse whitelist config file '%s': %w", filePath, err)
	}

	return wl, nil
}

// parseData parses YAML or JSON bytes into the whitelist mapping.
func (w *Whitelist) parseData(data []byte) error {
	// Try parsing as wrapped ConfigFile first
	var wrapped ConfigFile
	if err := yaml.Unmarshal(data, &wrapped); err == nil && len(wrapped.SPNWorkspaceWhitelist) > 0 {
		w.loadMap(wrapped.SPNWorkspaceWhitelist)
		return nil
	}

	// Try parsing as direct map[string][]string
	var direct map[string][]string
	if err := yaml.Unmarshal(data, &direct); err == nil && len(direct) > 0 {
		w.loadMap(direct)
		return nil
	}

	// Try JSON unmarshal as fallback
	var jsonWrapped ConfigFile
	if err := json.Unmarshal(data, &jsonWrapped); err == nil && len(jsonWrapped.SPNWorkspaceWhitelist) > 0 {
		w.loadMap(jsonWrapped.SPNWorkspaceWhitelist)
		return nil
	}

	var jsonDirect map[string][]string
	if err := json.Unmarshal(data, &jsonDirect); err == nil && len(jsonDirect) > 0 {
		w.loadMap(jsonDirect)
		return nil
	}

	// If file was empty or had no rules, return without error (disabled)
	return nil
}

// loadMap populates the normalized internal mapping.
func (w *Whitelist) loadMap(raw map[string][]string) {
	w.spnWorkspaces = make(map[string]map[string]bool)
	for spn, wsList := range raw {
		normSPN := strings.ToLower(strings.TrimSpace(spn))
		if normSPN == "" {
			continue
		}
		if _, exists := w.spnWorkspaces[normSPN]; !exists {
			w.spnWorkspaces[normSPN] = make(map[string]bool)
		}
		for _, wsID := range wsList {
			cleanWS := normalizeWorkspaceID(wsID)
			if cleanWS != "" {
				w.spnWorkspaces[normSPN][cleanWS] = true
			}
		}
	}
	w.enabled = len(w.spnWorkspaces) > 0
}

// IsEnabled returns true if the whitelist has active rules.
func (w *Whitelist) IsEnabled() bool {
	return w != nil && w.enabled
}

// CheckSPNWorkspace verifies if the calling SPN is authorized to manage the specified workspace ID.
// Returns (allowed, denialReason).
func (w *Whitelist) CheckSPNWorkspace(spnID, workspaceID string) (bool, string) {
	if !w.IsEnabled() {
		return true, ""
	}

	normSPN := strings.ToLower(strings.TrimSpace(spnID))
	allowedWorkspaces, found := w.spnWorkspaces[normSPN]
	if !found {
		return false, fmt.Sprintf("calling service principal '%s' is not in the authorized SPN whitelist", spnID)
	}

	cleanWS := normalizeWorkspaceID(workspaceID)
	if cleanWS == "" {
		return false, "workspace ID is required to verify calling SPN whitelist authorization"
	}

	// Support wildcard "*" allowing all workspaces for a specific SPN if configured
	if allowedWorkspaces["*"] || allowedWorkspaces[cleanWS] {
		return true, ""
	}

	return false, fmt.Sprintf("calling service principal '%s' is not authorized to manage workspace '%s' by whitelist policy",
		spnID, workspaceID)
}

// normalizeWorkspaceID strips common prefixes like "ws-" and parses integers cleanly.
func normalizeWorkspaceID(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "ws-")
	raw = strings.TrimPrefix(raw, "WS-")
	if raw == "*" {
		return "*"
	}
	if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return strconv.FormatInt(id, 10)
	}
	return raw
}
