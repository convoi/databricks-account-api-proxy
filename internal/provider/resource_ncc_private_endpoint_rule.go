package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"databricks-account-api-proxy/pkg/client"
)

var _ resource.Resource = &NCCPrivateEndpointRuleResource{}

type NCCPrivateEndpointRuleResource struct {
	client *client.Client
}

type NCCPrivateEndpointRuleModel struct {
	NCCID           types.String `tfsdk:"ncc_id"`
	RuleID          types.String `tfsdk:"rule_id"`
	ResourceID      types.String `tfsdk:"resource_id"`
	GroupID         types.String `tfsdk:"group_id"`
	EndpointName    types.String `tfsdk:"endpoint_name"`
	ConnectionState types.String `tfsdk:"connection_state"`
}

func NewNCCPrivateEndpointRuleResource() resource.Resource {
	return &NCCPrivateEndpointRuleResource{}
}

func (r *NCCPrivateEndpointRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ncc_private_endpoint_rule"
}

func (r *NCCPrivateEndpointRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Databricks NCC Private Endpoint Rule via the Scoped Proxy.",
		Attributes: map[string]schema.Attribute{
			"ncc_id": schema.StringAttribute{
				Description: "Network Connectivity Config ID.",
				Required:    true,
			},
			"rule_id": schema.StringAttribute{
				Description: "Private Endpoint Rule ID.",
				Computed:    true,
			},
			"resource_id": schema.StringAttribute{
				Description: "Cloud resource ID of the target service (e.g. Azure Storage / AWS VPC Endpoint Service).",
				Required:    true,
			},
			"group_id": schema.StringAttribute{
				Description: "Sub-resource / group ID (e.g. 'blob', 'dfs', 'sqlServer').",
				Required:    true,
			},
			"endpoint_name": schema.StringAttribute{
				Description: "Descriptive name for the endpoint rule.",
				Optional:    true,
			},
			"connection_state": schema.StringAttribute{
				Description: "Current connection state of the private endpoint rule.",
				Computed:    true,
			},
		},
	}
}

func (r *NCCPrivateEndpointRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *NCCPrivateEndpointRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NCCPrivateEndpointRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule := &client.PrivateEndpointRule{
		ResourceID:   plan.ResourceID.ValueString(),
		GroupID:      plan.GroupID.ValueString(),
		EndpointName: plan.EndpointName.ValueString(),
	}

	created, err := r.client.CreatePrivateEndpointRule(ctx, plan.NCCID.ValueString(), rule)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Private Endpoint Rule", err.Error())
		return
	}

	plan.RuleID = types.StringValue(created.RuleID)
	plan.ConnectionState = types.StringValue(created.ConnectionState)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NCCPrivateEndpointRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NCCPrivateEndpointRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, err := r.client.GetPrivateEndpointRule(ctx, state.NCCID.ValueString(), state.RuleID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Private Endpoint Rule", err.Error())
		return
	}

	state.ResourceID = types.StringValue(rule.ResourceID)
	state.GroupID = types.StringValue(rule.GroupID)
	state.EndpointName = types.StringValue(rule.EndpointName)
	state.ConnectionState = types.StringValue(rule.ConnectionState)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NCCPrivateEndpointRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan NCCPrivateEndpointRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NCCPrivateEndpointRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NCCPrivateEndpointRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeletePrivateEndpointRule(ctx, state.NCCID.ValueString(), state.RuleID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Private Endpoint Rule", err.Error())
		return
	}
}
