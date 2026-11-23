package provider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"databricks-account-api-proxy/pkg/client"
)

var _ provider.Provider = &DatabricksProxyProvider{}

// DatabricksProxyProvider defines the provider implementation.
type DatabricksProxyProvider struct {
	version string
}

// DatabricksProxyProviderModel describes the provider data model.
type DatabricksProxyProviderModel struct {
	ProxyURL      types.String `tfsdk:"proxy_url"`
	AccountID     types.String `tfsdk:"account_id"`
	Token         types.String `tfsdk:"token"`
	ClientID      types.String `tfsdk:"client_id"`
	OIDCToken     types.String `tfsdk:"oidc_token"`
	OIDCTokenFile types.String `tfsdk:"oidc_token_file"`
	WorkspaceURL  types.String `tfsdk:"workspace_url"`
	WorkspaceID   types.String `tfsdk:"workspace_id"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &DatabricksProxyProvider{
			version: version,
		}
	}
}

func (p *DatabricksProxyProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "databricks-proxy"
	resp.Version = p.version
}

func (p *DatabricksProxyProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider interacting with Databricks Account APIs via the Scoped RBAC Proxy.",
		Attributes: map[string]schema.Attribute{
			"proxy_url": schema.StringAttribute{
				Description: "The base URL of the Databricks Scoped Proxy (or env DATABRICKS_PROXY_URL).",
				Optional:    true,
			},
			"account_id": schema.StringAttribute{
				Description: "The Databricks Account ID (or env DATABRICKS_ACCOUNT_ID).",
				Optional:    true,
			},
			"token": schema.StringAttribute{
				Description: "The caller's Databricks OAuth bearer token (or env DATABRICKS_TOKEN).",
				Optional:    true,
				Sensitive:   true,
			},
			"client_id": schema.StringAttribute{
				Description: "Calling Service Principal application ID for Workload Identity (or env DATABRICKS_CLIENT_ID).",
				Optional:    true,
			},
			"oidc_token": schema.StringAttribute{
				Description: "External OIDC token JWT for Workload Identity Federation (or env DATABRICKS_OIDC_TOKEN).",
				Optional:    true,
				Sensitive:   true,
			},
			"oidc_token_file": schema.StringAttribute{
				Description: "Path to external OIDC token file (or env DATABRICKS_OIDC_TOKEN_FILE, AZURE_FEDERATED_TOKEN_FILE, AWS_WEB_IDENTITY_TOKEN_FILE).",
				Optional:    true,
			},
			"workspace_url": schema.StringAttribute{
				Description: "The caller's workspace URL for identity introspection (or env DATABRICKS_WORKSPACE_URL).",
				Optional:    true,
			},
			"workspace_id": schema.StringAttribute{
				Description: "The workspace ID for NCC operations (or env DATABRICKS_WORKSPACE_ID).",
				Optional:    true,
			},
		},
	}
}

func (p *DatabricksProxyProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data DatabricksProxyProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	proxyURL := os.Getenv("DATABRICKS_PROXY_URL")
	if !data.ProxyURL.IsNull() {
		proxyURL = data.ProxyURL.ValueString()
	}

	accountID := os.Getenv("DATABRICKS_ACCOUNT_ID")
	if !data.AccountID.IsNull() {
		accountID = data.AccountID.ValueString()
	}

	token := os.Getenv("DATABRICKS_TOKEN")
	if !data.Token.IsNull() {
		token = data.Token.ValueString()
	}

	workspaceURL := os.Getenv("DATABRICKS_WORKSPACE_URL")
	if !data.WorkspaceURL.IsNull() {
		workspaceURL = data.WorkspaceURL.ValueString()
	}

	workspaceID := os.Getenv("DATABRICKS_WORKSPACE_ID")
	if !data.WorkspaceID.IsNull() {
		workspaceID = data.WorkspaceID.ValueString()
	}

	// Workload Identity Federation resolution
	if token == "" {
		clientID := os.Getenv("DATABRICKS_CLIENT_ID")
		if !data.ClientID.IsNull() {
			clientID = data.ClientID.ValueString()
		}

		oidcToken := os.Getenv("DATABRICKS_OIDC_TOKEN")
		if !data.OIDCToken.IsNull() {
			oidcToken = data.OIDCToken.ValueString()
		}

		oidcTokenFile := os.Getenv("DATABRICKS_OIDC_TOKEN_FILE")
		if oidcTokenFile == "" {
			oidcTokenFile = os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
		}
		if oidcTokenFile == "" {
			oidcTokenFile = os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
		}
		if !data.OIDCTokenFile.IsNull() {
			oidcTokenFile = data.OIDCTokenFile.ValueString()
		}

		if oidcToken == "" && oidcTokenFile != "" {
			tokenBytes, err := os.ReadFile(oidcTokenFile)
			if err != nil {
				resp.Diagnostics.AddError("Failed to Read OIDC Token File", err.Error())
				return
			}
			oidcToken = strings.TrimSpace(string(tokenBytes))
		}

		if clientID != "" && oidcToken != "" {
			// Resolve OIDC token exchange endpoint
			endpointHost := workspaceURL
			if endpointHost == "" {
				endpointHost = proxyURL
			}
			tokenEndpoint := fmt.Sprintf("%s/oidc/v1/token", strings.TrimRight(endpointHost, "/"))

			exchangedToken, err := client.ExchangeWorkloadIdentityToken(ctx, nil, tokenEndpoint, clientID, oidcToken)
			if err != nil {
				resp.Diagnostics.AddError("Workload Identity Token Exchange Failed", err.Error())
				return
			}
			token = exchangedToken
		}
	}

	if proxyURL == "" {
		resp.Diagnostics.AddError("Missing Proxy URL", "proxy_url must be configured on provider or via DATABRICKS_PROXY_URL")
		return
	}
	if accountID == "" {
		resp.Diagnostics.AddError("Missing Account ID", "account_id must be configured on provider or via DATABRICKS_ACCOUNT_ID")
		return
	}
	if token == "" {
		resp.Diagnostics.AddError("Missing Caller Authentication", "Must configure either 'token' or Workload Identity ('client_id' and 'oidc_token' / 'oidc_token_file')")
		return
	}

	c := client.NewClient(client.ClientConfig{
		ProxyURL:     proxyURL,
		AccountID:    accountID,
		CallerToken:  token,
		WorkspaceURL: workspaceURL,
		WorkspaceID:  workspaceID,
	})

	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *DatabricksProxyProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSPNFederationPolicyResource,
		NewNCCPrivateEndpointRuleResource,
	}
}

func (p *DatabricksProxyProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
