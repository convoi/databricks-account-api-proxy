package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"databricks-account-api-proxy/pkg/client"
)

var _ resource.Resource = &SPNFederationPolicyResource{}

type SPNFederationPolicyResource struct {
	client *client.Client
}

type SPNFederationPolicyModel struct {
	TargetSPNID types.String `tfsdk:"target_spn_id"`
	PolicyID    types.String `tfsdk:"policy_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Issuer      types.String `tfsdk:"issuer"`
	Subject     types.String `tfsdk:"subject"`
	Audiences   types.List   `tfsdk:"audiences"`
}

func NewSPNFederationPolicyResource() resource.Resource {
	return &SPNFederationPolicyResource{}
}

func (r *SPNFederationPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spn_federation_policy"
}

func (r *SPNFederationPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Databricks Service Principal Federation Policy via the Scoped Proxy.",
		Attributes: map[string]schema.Attribute{
			"target_spn_id": schema.StringAttribute{
				Description: "Application ID or Databricks ID of the target Service Principal.",
				Required:    true,
			},
			"policy_id": schema.StringAttribute{
				Description: "Unique policy identifier.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Human-readable name of the federation policy.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the federation policy.",
				Optional:    true,
			},
			"issuer": schema.StringAttribute{
				Description: "OIDC token issuer URL.",
				Required:    true,
			},
			"subject": schema.StringAttribute{
				Description: "OIDC token subject claim.",
				Required:    true,
			},
			"audiences": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Allowed audiences for the OIDC token.",
				Required:    true,
			},
		},
	}
}

func (r *SPNFederationPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	r.client = c
}

func (r *SPNFederationPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SPNFederationPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var audiences []string
	resp.Diagnostics.Append(plan.Audiences.ElementsAs(ctx, &audiences, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pol := &client.FederationPolicy{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		Issuer:      plan.Issuer.ValueString(),
		Subject:     plan.Subject.ValueString(),
		Audiences:   audiences,
	}

	created, err := r.client.CreateFederationPolicy(ctx, plan.TargetSPNID.ValueString(), pol)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Federation Policy", err.Error())
		return
	}

	plan.PolicyID = types.StringValue(created.PolicyID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SPNFederationPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state SPNFederationPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pol, err := r.client.GetFederationPolicy(ctx, state.TargetSPNID.ValueString(), state.PolicyID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Federation Policy", err.Error())
		return
	}

	state.Name = types.StringValue(pol.Name)
	state.Description = types.StringValue(pol.Description)
	state.Issuer = types.StringValue(pol.Issuer)
	state.Subject = types.StringValue(pol.Subject)

	audList, diags := types.ListValueFrom(ctx, types.StringType, pol.Audiences)
	resp.Diagnostics.Append(diags...)
	state.Audiences = audList

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SPNFederationPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Re-create or apply update
	var plan SPNFederationPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SPNFederationPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state SPNFederationPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteFederationPolicy(ctx, state.TargetSPNID.ValueString(), state.PolicyID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Federation Policy", err.Error())
		return
	}
}
