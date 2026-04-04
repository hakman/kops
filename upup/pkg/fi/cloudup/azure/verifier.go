/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"k8s.io/kops/pkg/bootstrap"
	"k8s.io/kops/pkg/wellknownports"
)

const (
	// InstanceGroupNameTag is the key of the tag used to identify an instance group that VM belongs to.
	InstanceGroupNameTag = "kops.k8s.io_instancegroup"
)

// AzureVerifierOptions configures the Azure bootstrap token verifier.
type AzureVerifierOptions struct {
	ClusterName string `json:"clusterName,omitempty"`
}

type azureVerifier struct {
	client      *client
	clusterName string
}

var _ bootstrap.Verifier = (*azureVerifier)(nil)

// NewAzureVerifier returns a verifier that validates Azure IMDS attestation
// tokens and resolves the claimed VM identity through the Azure API.
func NewAzureVerifier(ctx context.Context, opt *AzureVerifierOptions) (bootstrap.Verifier, error) {
	azureClient, err := newVerifierClient()
	if err != nil {
		return nil, err
	}

	if opt == nil || opt.ClusterName == "" {
		return nil, fmt.Errorf("determining cluster name")
	}

	return &azureVerifier{
		client:      azureClient,
		clusterName: opt.ClusterName,
	}, nil
}

// VerifyToken validates the Azure attestation token, confirms the claimed VM
// through the Azure API, and returns the node bootstrap identity.
func (a azureVerifier) VerifyToken(ctx context.Context, rawRequest *http.Request, token string, body []byte) (*bootstrap.VerifyResult, error) {
	if !strings.HasPrefix(token, AzureAuthenticationTokenPrefix) {
		return nil, bootstrap.ErrNotThisVerifier
	}

	// Token format: "x-azure-id <resourceID> <base64-pkcs7-signature>"
	v := strings.Split(strings.TrimPrefix(token, AzureAuthenticationTokenPrefix), " ")
	if len(v) != 2 {
		return nil, fmt.Errorf("incorrect token format")
	}
	resourceID := v[0]
	signature := v[1]

	// Parse the resource ID early to reject malformed tokens before expensive crypto.
	res, err := arm.ParseResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("parsing resource ID: %w", err)
	}

	// Reject resource IDs outside the verifier's own subscription / resource
	// group. The Azure API lookup below is already scoped to kops-controller's
	// subscription and resource group, so any claim that names a different
	// location cannot describe a cluster VM. Failing here avoids a wasted
	// Azure API call and makes the scope explicit instead of implicit.
	if !strings.EqualFold(res.SubscriptionID, a.client.subscriptionID) {
		return nil, fmt.Errorf("resource ID subscription %q does not match verifier subscription", res.SubscriptionID)
	}
	if !strings.EqualFold(res.ResourceGroupName, a.client.resourceGroup) {
		return nil, fmt.Errorf("resource ID resource group %q does not match verifier resource group", res.ResourceGroupName)
	}

	// Verify the PKCS7 attested document: signature, certificate chain, nonce, and expiration.
	data, err := verifyAttestedDocument(signature, body)
	if err != nil {
		return nil, err
	}

	// Look up the VM or VMSS VM via the Azure API using the resource ID,
	// cross-verify the attested vmId, and extract node identity.
	var nodeName, igName string
	var addrs, challengeEndpoints []string

	switch res.ResourceType.String() {
	case "Microsoft.Compute/virtualMachines":
		vmName := res.Name

		// Fetch the VM from the Azure API.
		vm, err := a.client.vmsClient.Get(ctx, a.client.resourceGroup, vmName, nil)
		if err != nil {
			return nil, fmt.Errorf("getting info for VM %q: %w", vmName, err)
		}
		if vm.Properties == nil || vm.Properties.VMID == nil {
			return nil, fmt.Errorf("determining VMID for VM %q", vmName)
		}

		// Cross-verify: the vmId from the cryptographically signed attested document
		// must match the vmId from the Azure API for the claimed resource ID.
		if data.VMId != *vm.Properties.VMID {
			return nil, fmt.Errorf("attested vmId %q does not match VM %q (API vmId %q)", data.VMId, vmName, *vm.Properties.VMID)
		}
		if vm.Properties.OSProfile == nil || vm.Properties.OSProfile.ComputerName == nil || *vm.Properties.OSProfile.ComputerName == "" {
			return nil, fmt.Errorf("determining ComputerName for VM %q", vmName)
		}

		// Extract node name and instance group from VM metadata.
		nodeName = strings.ToLower(*vm.Properties.OSProfile.ComputerName)
		if igNameTag, ok := vm.Tags[InstanceGroupNameTag]; ok && igNameTag != nil {
			igName = *igNameTag
		} else {
			return nil, fmt.Errorf("determining IG name for VM %q", vmName)
		}

		// Collect private IP addresses from the VM's network interface.
		ni, err := a.client.nisClient.Get(ctx, a.client.resourceGroup, nodeName, nil)
		if err != nil {
			return nil, fmt.Errorf("getting info for VM network interface %q: %w", vmName, err)
		}

		for _, ipc := range ni.Properties.IPConfigurations {
			if ipc.Properties != nil && ipc.Properties.PrivateIPAddress != nil {
				addrs = append(addrs, *ipc.Properties.PrivateIPAddress)
				challengeEndpoints = append(challengeEndpoints, net.JoinHostPort(*ipc.Properties.PrivateIPAddress, strconv.Itoa(wellknownports.NodeupChallenge)))
			}
		}

	case "Microsoft.Compute/virtualMachineScaleSets/virtualMachines":
		vmssName := res.Parent.Name
		vmssIndex := res.Name

		// Verify the VMSS belongs to this cluster.
		if !strings.HasSuffix(vmssName, "."+a.clusterName) {
			return nil, fmt.Errorf("matching cluster name %q to VMSS %q", a.clusterName, vmssName)
		}

		// Fetch the VMSS VM from the Azure API.
		vm, err := a.client.vmssVMsClient.Get(ctx, a.client.resourceGroup, vmssName, vmssIndex, nil)
		if err != nil {
			return nil, fmt.Errorf("getting info for VMSS VM %q #%s: %w", vmssName, vmssIndex, err)
		}
		if vm.Properties == nil || vm.Properties.VMID == nil {
			return nil, fmt.Errorf("determining VMID for VMSS %q VM #%s", vmssName, vmssIndex)
		}

		// Cross-verify: the vmId from the cryptographically signed attested document
		// must match the vmId from the Azure API for the claimed resource ID.
		if data.VMId != *vm.Properties.VMID {
			return nil, fmt.Errorf("attested vmId %q does not match VMSS %q VM #%s (API vmId %q)", data.VMId, vmssName, vmssIndex, *vm.Properties.VMID)
		}
		if vm.Properties.OSProfile == nil || vm.Properties.OSProfile.ComputerName == nil || *vm.Properties.OSProfile.ComputerName == "" {
			return nil, fmt.Errorf("determining ComputerName for VMSS %q VM #%s", vmssName, vmssIndex)
		}

		// Extract node name and instance group from VMSS VM metadata.
		nodeName = strings.ToLower(*vm.Properties.OSProfile.ComputerName)
		if igNameTag, ok := vm.Tags[InstanceGroupNameTag]; ok && igNameTag != nil {
			igName = *igNameTag
		} else {
			return nil, fmt.Errorf("determining IG name for VM %q", vmssName)
		}

		// Collect private IP addresses from the VMSS VM's network interface.
		ni, err := a.client.nisClient.GetVirtualMachineScaleSetNetworkInterface(ctx, a.client.resourceGroup, vmssName, vmssIndex, vmssName, nil)
		if err != nil {
			return nil, fmt.Errorf("getting info for VMSS VM network interface %q #%s: %w", vmssName, vmssIndex, err)
		}

		for _, ipc := range ni.Properties.IPConfigurations {
			if ipc.Properties != nil && ipc.Properties.PrivateIPAddress != nil {
				addrs = append(addrs, *ipc.Properties.PrivateIPAddress)
				challengeEndpoints = append(challengeEndpoints, net.JoinHostPort(*ipc.Properties.PrivateIPAddress, strconv.Itoa(wellknownports.NodeupChallenge)))
			}
		}

	default:
		return nil, fmt.Errorf("unsupported resource type %q", res.ResourceType)
	}

	// Validate that we found at least one address and challenge endpoint.
	if len(addrs) == 0 {
		return nil, fmt.Errorf("determining certificate alternate names for node %q", nodeName)
	}
	if len(challengeEndpoints) == 0 {
		return nil, fmt.Errorf("determining challenge endpoint for node %q", nodeName)
	}

	result := &bootstrap.VerifyResult{
		NodeName:          nodeName,
		InstanceGroupName: igName,
		CertificateNames:  addrs,
		ChallengeEndpoint: challengeEndpoints[0],
	}

	return result, nil
}

// client is an Azure client.
type client struct {
	subscriptionID string
	resourceGroup  string
	nisClient      *network.InterfacesClient
	vmsClient      *compute.VirtualMachinesClient
	vmssVMsClient  *compute.VirtualMachineScaleSetVMsClient
}

// newVerifierClient builds Azure API clients scoped to the local instance's
// subscription and resource group from IMDS metadata.
func newVerifierClient() (*client, error) {
	metadata, err := QueryComputeInstanceMetadata()
	if err != nil || metadata == nil {
		return nil, fmt.Errorf("getting instance metadata: %w", err)
	}
	if metadata.ResourceGroupName == "" {
		return nil, fmt.Errorf("empty resource group name")
	}
	if metadata.SubscriptionID == "" {
		return nil, fmt.Errorf("empty subscription ID")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating an identity: %w", err)
	}

	nisClient, err := network.NewInterfacesClient(metadata.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating interfaces client: %w", err)
	}
	vmsClient, err := compute.NewVirtualMachinesClient(metadata.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating VMs client: %w", err)
	}
	vmssVMsClient, err := compute.NewVirtualMachineScaleSetVMsClient(metadata.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating VMSSVMs client: %w", err)
	}

	return &client{
		subscriptionID: metadata.SubscriptionID,
		resourceGroup:  metadata.ResourceGroupName,
		nisClient:      nisClient,
		vmsClient:      vmsClient,
		vmssVMsClient:  vmssVMsClient,
	}, nil
}
