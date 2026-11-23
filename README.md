# Databricks Account API Scoped RBAC Proxy & Terraform Provider

A high-performance, secure HTTP reverse-proxy and authorization broker written in **Go** that allows non-Account-Admin Databricks users and Service Principals (SPNs) to execute a strictly allowlisted subset of Databricks Account API operations, governed by dynamic RBAC checks.

It also includes a companion **Terraform Provider** (`terraform-provider-databricks-proxy`) built with HashiCorp's `terraform-plugin-framework` to allow teams to manage federation policies and private endpoint rules natively via Infrastructure-as-Code without needing Account Admin privileges.

---

## Why Go?

1. **Native Terraform Ecosystem**: Terraform providers are built exclusively in Go. Developing the proxy and client models in Go allows the Terraform provider to directly share the SDK, API contracts, and HTTP transport without duplicate implementations or cross-language serialization layers.
2. **Minimal Footprint & Security**: Compiles into a single, self-contained static binary running inside a minimal, non-root scratch/Alpine container (<20 MB) with zero runtime dependencies.
3. **High Performance**: Native goroutine concurrency, instant startup (<5 ms), and thread-safe in-memory TTL caching for OAuth tokens and workspace resolution.

---

## Architecture & Security Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Caller (SPN or User)
    participant Proxy as Scoped RBAC Proxy
    participant WS as Databricks Workspace SCIM
    participant Accounts as Databricks Account API

    Caller->>Proxy: Request (Bearer caller_token, X-Databricks-Workspace-*)
    Note over Proxy: 1. Caller Authentication & SPN Whitelist Check
    Proxy->>WS: GET /api/2.0/preview/scim/v2/Me (caller_token)
    WS-->>Proxy: SCIM Identity (Principal ID, numeric ID, groups)
    
    Note over Proxy: 2. Dynamic RBAC Policy Evaluation
    alt Policy 1 - SPN Federation Policies
        Proxy->>Accounts: GET access-control/rule-sets/.../servicePrincipals/target_spn (admin_token)
        Accounts-->>Proxy: Rule Set (roles/servicePrincipal.manager)
        Note over Proxy: Verify caller principal or group in grant_rules
    else Policy 2 - NCC Private Endpoint Rules
        Proxy->>Accounts: GET accounts/acc_id/workspaces/ws_id (admin_token)
        Accounts-->>Proxy: Workspace NCC binding
        Proxy->>Accounts: GET accounts/acc_id/workspaces (admin_token)
        Accounts-->>Proxy: All workspaces (Verify 1 to 1 isolation check)
        Proxy->>WS: Verify caller in admins group
    end

    alt Authorization Passed
        Note over Proxy: 3. Upstream Forwarding
        Proxy->>Accounts: Forward request (Strip caller token and inject privileged Admin token)
        Accounts-->>Proxy: Upstream response
        Proxy-->>Caller: Proxied response + HTTP status
        Note over Proxy: Audit Log - ALLOW
    else Authorization Failed
        Proxy-->>Caller: 403 Forbidden (JSON error response)
        Note over Proxy: Audit Log - DENY
    end
```

---

## Allowlisted Endpoints & Policies

### Policy 1: Service Principal Operations
- **Allowlisted Endpoints:**
  - `GET /api/2.0/accounts/{account_id}/servicePrincipals/{target_spn_id}`
  - `GET`, `POST`, `PATCH`, `DELETE /api/2.0/accounts/{account_id}/servicePrincipals/{target_spn_id}/federationPolicies`
  - `GET`, `POST`, `PATCH`, `DELETE /api/2.0/accounts/{account_id}/servicePrincipals/{target_spn_id}/federationPolicies/{policy_id}`
- **Authorization Rule:**
  1. Proxy fetches `GET /api/2.0/preview/accounts/{account_id}/access-control/rule-sets/accounts/{account_id}/servicePrincipals/{target_spn_id}` using its privileged Account Admin token.
  2. Locates the rule where `role == "roles/servicePrincipal.manager"`.
  3. Verifies that `principals` contains `servicePrincipals/{caller_id}`, `users/{caller_email}`, or `groups/{caller_group}`.

### Policy 2: Network Connectivity Config (NCC) Rules
- **Allowlisted Endpoints:**
  - `GET /api/2.0/accounts/{account_id}/network-connectivity-configs/{ncc_id}`
  - `GET`, `POST`, `PATCH`, `DELETE /api/2.0/accounts/{account_id}/network-connectivity-configs/{ncc_id}/private-endpoint-rules`
  - `GET`, `PATCH`, `DELETE /api/2.0/accounts/{account_id}/network-connectivity-configs/{ncc_id}/private-endpoint-rules/{rule_id}`
- **Required Header:** `X-Databricks-Workspace-Id: <workspace_id>`
- **Authorization Rule (All 3 checks must pass):**
  1. **Workspace-to-NCC Binding**: Verifies `target_ws.network_connectivity_config_id == {ncc_id}`.
  2. **1:1 Isolation Check (Blast Radius Prevention)**: Queries all workspaces in the account to ensure **no other workspace** is attached to `{ncc_id}`.
  3. **Workspace Admin Verification**: Verifies the caller is a member of the built-in `admins` group on that workspace.

### Default Deny & Structured Audit Logging
- Any non-allowlisted path or HTTP method (such as `DELETE /servicePrincipals/{id}`) returns `404` or `405/403` with a `DENY` audit record.
- Every request emits a structured JSON audit line containing:
  - `timestamp`, `request_id`, `caller_identity`, `target_resource`, `http_method`, `path`, `policy_evaluated`, `decision` (`ALLOW` / `DENY`), `denial_reason`, and `upstream_status_code`.
  - Sensitive tokens are **never** logged.

---

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|---|---|---|
| `DATABRICKS_ACCOUNT_ID` | Databricks Account UUID | *(Optional fallback)* |
| `DATABRICKS_ACCOUNTS_HOST` | Accounts API endpoint (AWS/Azure/GCP) | `https://accounts.cloud.databricks.com` |
| `PROXY_CLIENT_ID` | Privileged Account Admin SPN Client ID | **Required** |
| `PROXY_CLIENT_SECRET` | Privileged Account Admin SPN Client Secret | *(Required if not using Workload Identity)* |
| `PROXY_OIDC_TOKEN` | Direct external OIDC JWT assertion for Workload Identity | *(Optional)* |
| `PROXY_OIDC_TOKEN_FILE` | Path to OIDC token file (also auto-detects `AZURE_FEDERATED_TOKEN_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`) | *(Optional)* |
| `PROXY_LISTEN_ADDR` | Listening host:port | `:8080` |
| `PROXY_CONFIG_FILE` | Path to whitelist mapping YAML/JSON file | `config.yaml` (if present) |
| `CACHE_TTL_SECONDS` | In-memory token/workspace cache TTL | `60` |
| `LOG_LEVEL` | Log verbosity (`INFO`, `DEBUG`) | `INFO` |

---

## Calling SPN Workspace Whitelist (Defense-in-Depth)

To further constrain proxy access, you can supply a configuration file (`config.yaml` or via `PROXY_CONFIG_FILE`) mapping **calling Service Principals** to the specific list of workspace IDs they are allowed to manage:

```yaml
# config.yaml
spn_workspace_whitelist:
  # Calling SPN UUID -> list of authorized workspace IDs
  "11111111-2222-3333-4444-555555555555":
    - "1234567890123456" # Dev Workspace
    - "9876543210987654" # Staging Workspace

  "aaaa-bbbb-cccc-dddd-eeeeeeeeeeee":
    - "1234567890123456"
```

> [!IMPORTANT]
> The whitelist check is an additional defense-in-depth boundary. **All other required permissions still apply** (being a verified workspace admin on the workspace, having `roles/servicePrincipal.manager` on the target SPN, and the 1:1 NCC blast radius isolation check).

---

## Building & Running

### Local Binary
```bash
# Build proxy and provider
go build -o proxy ./cmd/proxy
go build -o terraform-provider-databricks-proxy ./cmd/terraform-provider-databricks-proxy

# Run tests
go test -v ./...

# Start proxy
export PROXY_CLIENT_ID="<admin-spn-client-id>"
export PROXY_CLIENT_SECRET="<admin-spn-secret>"
./proxy
```

### Docker
```bash
# Build Docker image
docker build -t databricks-account-api-proxy:latest .

# Run container (non-root UID 10001)
docker run -d \
  -p 8080:8080 \
  -e PROXY_CLIENT_ID="<client-id>" \
  -e PROXY_CLIENT_SECRET="<client-secret>" \
  databricks-account-api-proxy:latest
```

---

## Sample `curl` Commands

### 1. Create SPN Federation Policy (Policy 1)
```bash
curl -X POST http://localhost:8080/api/2.0/accounts/11111111-2222-3333-4444-555555555555/servicePrincipals/aaaa-bbbb-cccc-dddd/federationPolicies \
  -H "Authorization: Bearer dapi1234567890abcdef" \
  -H "X-Databricks-Workspace-Url: https://dbc-xxxx-xxxx.cloud.databricks.com" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "github-actions-policy",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:my-org/my-repo:ref:refs/heads/main",
    "audiences": ["https://accounts.cloud.databricks.com"]
  }'
```

### 2. Create NCC Private Endpoint Rule (Policy 2)
```bash
curl -X POST http://localhost:8080/api/2.0/accounts/11111111-2222-3333-4444-555555555555/network-connectivity-configs/ncc-12345/private-endpoint-rules \
  -H "Authorization: Bearer dapi1234567890abcdef" \
  -H "X-Databricks-Workspace-Id: 987654321012345" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mysa",
    "group_id": "blob",
    "endpoint_name": "ep-blob-storage"
  }'
```

### 3. Blocked Endpoint (Default Deny)
```bash
curl -X DELETE http://localhost:8080/api/2.0/accounts/11111111-2222-3333-4444-555555555555/servicePrincipals/aaaa-bbbb-cccc-dddd \
  -H "Authorization: Bearer dapi1234567890abcdef" \
  -H "X-Databricks-Workspace-Url: https://dbc-xxxx-xxxx.cloud.databricks.com"

# Response: HTTP 405 Method Not Allowed / 403 Forbidden
# {"error":"method not allowlisted by proxy"}
```

---

## Terraform Provider Integration

Use the companion Terraform provider to manage scoped Databricks resources through the proxy.

### A. Static Token Authentication
```hcl
provider "databricks-proxy" {
  proxy_url     = "http://proxy.internal.company.com:8080"
  account_id    = "11111111-2222-3333-4444-555555555555"
  token         = var.databricks_caller_token
  workspace_url = "https://dbc-xxxx-xxxx.cloud.databricks.com"
  workspace_id  = "987654321012345"
}
```

### B. Workload Identity Authentication (Kubernetes, GitHub Actions, Azure, AWS)
No long-lived secrets needed! The provider automatically exchanges external OIDC assertions via RFC 7523 before making scoped proxy requests:

```hcl
provider "databricks-proxy" {
  proxy_url       = "http://proxy.internal.company.com:8080"
  account_id      = "11111111-2222-3333-4444-555555555555"
  workspace_url   = "https://dbc-xxxx-xxxx.cloud.databricks.com"
  workspace_id    = "987654321012345"

  # Workload Identity Federation:
  client_id       = "aaaa-bbbb-cccc-dddd"
  oidc_token_file = "/var/run/secrets/tokens/jwt" # e.g. Kubernetes projected token or Azure/AWS federated file
  # Or use direct token:
  # oidc_token    = var.actions_id_token
}
```

### Resources

```hcl
# Manage SPN Federation Policy without Account Admin rights
resource "databricks-proxy_spn_federation_policy" "github_oidc" {
  target_spn_id = "aaaa-bbbb-cccc-dddd"
  name          = "github-actions-oidc"
  description   = "Federation policy for CI/CD GitHub Actions"
  issuer        = "https://token.actions.githubusercontent.com"
  subject       = "repo:my-company/data-pipelines:environment:prod"
  audiences     = ["https://accounts.cloud.databricks.com"]
}

# Manage NCC Private Endpoint Rule safely bounded to 1 workspace
resource "databricks-proxy_ncc_private_endpoint_rule" "storage_rule" {
  ncc_id        = "ncc-12345"
  resource_id   = "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/datalakeprod"
  group_id      = "dfs"
  endpoint_name = "ep-datalake-dfs"
}
```

---

## Automated Multi-Platform Releases (GitHub Actions)

This repository includes a free-tier compatible GitHub Actions workflow (`.github/workflows/release.yml`) and GoReleaser configuration (`.goreleaser.yml`).

### How It Works on GitHub Free Tier
- **Cross-Compilation on a Single Linux Runner**: Go natively cross-compiles for **Linux**, **macOS (`darwin`)**, and **Windows** (`amd64` and `arm64`) on a single `ubuntu-latest` runner without needing expensive macOS or Windows runner minutes.
- **Public vs. Private Repositories**:
  - **Public Repositories**: GitHub Actions is 100% free with unlimited minutes.
  - **Private Repositories**: Free accounts include **2,000 free Linux minutes/month**, and this cross-compilation workflow takes under 1 minute per release.
- **Triggering a Release**:
  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```
  Pushing a `v*` tag runs the test suite and publishes a GitHub Release containing zip archives and `SHA256SUMS` for both the proxy and `terraform-provider-databricks-proxy` across all 3 major operating systems.

---

## Versioning & License

- **Current Version**: `0.1.0` (tracked in [`VERSION`](file:///C:/Users/jhees/IdeaProjects/databricks-account-api-proxy/VERSION))
- **License**: Dedicated to the **Public Domain** ([`LICENSE`](file:///C:/Users/jhees/IdeaProjects/databricks-account-api-proxy/LICENSE)).

