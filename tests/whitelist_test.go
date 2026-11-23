package tests

import (
	"os"
	"path/filepath"
	"testing"

	"databricks-account-api-proxy/internal/whitelist"
)

func TestWhitelist_ParsingAndChecking(t *testing.T) {
	yamlContent := `
spn_workspace_whitelist:
  "11111111-1111-1111-1111-111111111111":
    - "1234567890"
    - "ws-9876543210"
  "22222222-2222-2222-2222-222222222222":
    - "*"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	wl, err := whitelist.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("unexpected error loading whitelist: %v", err)
	}

	if !wl.IsEnabled() {
		t.Fatalf("expected whitelist to be enabled")
	}

	// 1. Calling SPN 1 on allowed workspace (direct numeric)
	allowed, reason := wl.CheckSPNWorkspace("11111111-1111-1111-1111-111111111111", "1234567890")
	if !allowed {
		t.Errorf("expected allowed=true, got false: %s", reason)
	}

	// 2. Calling SPN 1 on allowed workspace (with ws- prefix normalized)
	allowed, reason = wl.CheckSPNWorkspace("11111111-1111-1111-1111-111111111111", "ws-1234567890")
	if !allowed {
		t.Errorf("expected allowed=true for normalized ws- prefix, got false: %s", reason)
	}

	// 3. Calling SPN 1 on second allowed workspace
	allowed, reason = wl.CheckSPNWorkspace("11111111-1111-1111-1111-111111111111", "9876543210")
	if !allowed {
		t.Errorf("expected allowed=true, got false: %s", reason)
	}

	// 4. Calling SPN 1 on unauthorized workspace
	allowed, reason = wl.CheckSPNWorkspace("11111111-1111-1111-1111-111111111111", "9999999999")
	if allowed {
		t.Errorf("expected allowed=false for unauthorized workspace, got true")
	}

	// 5. Calling SPN 2 with wildcard "*"
	allowed, reason = wl.CheckSPNWorkspace("22222222-2222-2222-2222-222222222222", "anything-123")
	if !allowed {
		t.Errorf("expected allowed=true for wildcard SPN, got false: %s", reason)
	}

	// 6. Calling SPN not in whitelist
	allowed, reason = wl.CheckSPNWorkspace("unknown-spn-uuid", "1234567890")
	if allowed {
		t.Errorf("expected allowed=false for unlisted SPN, got true")
	}
}

func TestWhitelist_DisabledWhenNoFileOrEmpty(t *testing.T) {
	// Empty path
	wl, err := whitelist.LoadFromFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wl.IsEnabled() {
		t.Errorf("expected whitelist to be disabled when no file is passed")
	}

	allowed, _ := wl.CheckSPNWorkspace("any-spn", "any-ws")
	if !allowed {
		t.Errorf("expected allowed=true when whitelist is disabled")
	}
}
