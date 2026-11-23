package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"databricks-account-api-proxy/pkg/client"
)

var (
	_ resource.Resource                = &SPNFederationPolicyResource{}
	_ resource.ResourceWithImportState = &SPNFederationPolicyResource{}
)

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
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"policy_id": schema.StringAttribute{
				Description: "Unique policy identifier.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
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
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading Federation Policy", err.Error())
		return
	}

	state.Name = types.StringValue(pol.Name)
	if pol.Description != "" || !state.Description.IsNull() {
		state.Description = types.StringValue(pol.Description)
	}
	state.Issuer = types.StringValue(pol.Issuer)
	state.Subject = types.StringValue(pol.Subject)

	audList, diags := types.ListValueFrom(ctx, types.StringType, pol.Audiences)
	resp.Diagnostics.Append(diags...)
	state.Audiences = audList

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SPNFederationPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SPNFederationPolicyModel
	var state SPNFederationPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var audiences []string
	resp.Diagnostics.Append(plan.Audiences.ElementsAs(ctx, &audiences, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pol := &client.FederationPolicy{
		PolicyID:    state.PolicyID.ValueString(),
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		Issuer:      plan.Issuer.ValueString(),
		Subject:     plan.Subject.ValueString(),
		Audiences:   audiences,
	}

	_, err := r.client.UpdateFederationPolicy(ctx, plan.TargetSPNID.ValueString(), state.PolicyID.ValueString(), pol)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Federation Policy", err.Error())
		return
	}

	plan.PolicyID = state.PolicyID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SPNFederationPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state SPNFederationPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteFederationPolicy(ctx, state.TargetSPNID.ValueString(), state.PolicyID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error Deleting Federation Policy", err.Error())
		return
	}
}

func (r *SPNFederationPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Expected format: "<target_spn_id>/<policy_id>"
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			"Expected import identifier in format: <target_spn_id>/<policy_id>",
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("target_spn_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_id"), parts[1])...)
}
