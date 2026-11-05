/*
Copyright 2017 The Kubernetes Authors.

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

package awstasks

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"k8s.io/kops/cloudmock/aws/mockec2"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awsup"
)

func TestSharedEgressOnlyInternetGatewayDoesNotRename(t *testing.T) {
	ctx := context.TODO()

	cloud := awsup.BuildMockAWSCloud("us-east-1", "abc")
	c := &mockec2.MockEC2{}
	cloud.MockEC2 = c

	// Pre-create the vpc / subnet
	vpc, err := c.CreateVpc(ctx, &ec2.CreateVpcInput{
		CidrBlock: aws.String("172.20.0.0/16"),
	})
	if err != nil {
		t.Fatalf("error creating test VPC: %v", err)
	}
	_, err = c.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{aws.ToString(vpc.Vpc.VpcId)},
		Tags: []ec2types.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String("ExistingVPC"),
			},
		},
	})
	if err != nil {
		t.Fatalf("error tagging test vpc: %v", err)
	}

	internetGateway, err := c.CreateEgressOnlyInternetGateway(ctx, &ec2.CreateEgressOnlyInternetGatewayInput{
		VpcId: vpc.Vpc.VpcId,
		TagSpecifications: awsup.EC2TagSpecification(ec2types.ResourceTypeEgressOnlyInternetGateway, map[string]string{
			"Name": "ExistingInternetGateway",
		}),
	})
	if err != nil {
		t.Fatalf("error creating test eigw: %v", err)
	}

	// We define a function so we can rebuild the tasks, because we modify in-place when running
	buildTasks := func() map[string]fi.CloudupTask {
		vpc1 := &VPC{
			Name:      s("vpc1"),
			Lifecycle: fi.LifecycleSync,
			CIDR:      s("172.20.0.0/16"),
			Tags:      map[string]string{"kubernetes.io/cluster/cluster.example.com": "shared"},
			Shared:    new(true),
			ID:        vpc.Vpc.VpcId,
		}
		eigw1 := &EgressOnlyInternetGateway{
			Name:      s("eigw1"),
			Lifecycle: fi.LifecycleSync,
			VPC:       vpc1,
			Shared:    new(true),
			ID:        internetGateway.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId,
			Tags:      make(map[string]string),
		}

		return map[string]fi.CloudupTask{
			"eigw1": eigw1,
			"vpc1":  vpc1,
		}
	}

	{
		allTasks := buildTasks()
		eigw1 := allTasks["eigw1"].(*EgressOnlyInternetGateway)

		runTasks(t, cloud, allTasks)

		if fi.ValueOf(eigw1.ID) == "" {
			t.Fatalf("ID not set after create")
		}

		if len(c.EgressOnlyInternetGatewayIds()) != 1 {
			t.Fatalf("Expected exactly one EgressOnlyInternetGateway; found %v", c.EgressOnlyInternetGatewayIds())
		}

		actual := c.FindEgressOnlyInternetGateway(*internetGateway.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId)
		if actual == nil {
			t.Fatalf("EgressOnlyInternetGateway created but then not found")
		}
		expected := &ec2types.EgressOnlyInternetGateway{
			EgressOnlyInternetGatewayId: aws.String("eigw-1"),
			Tags: buildTags(map[string]string{
				"Name": "ExistingInternetGateway",
			}),
			Attachments: []ec2types.InternetGatewayAttachment{
				{
					VpcId: vpc.Vpc.VpcId,
					State: ec2types.AttachmentStatusAttached,
				},
			},
		}

		mockec2.SortTags(expected.Tags)
		mockec2.SortTags(actual.Tags)

		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("Unexpected EgressOnlyInternetGateway: expected=%v actual=%v", expected, actual)
		}
	}

	{
		allTasks := buildTasks()
		checkNoChanges(t, ctx, cloud, allTasks)
	}
}

// TestSharedEgressOnlyInternetGatewayFoundByVPC checks that a shared EgressOnlyInternetGateway
// with no known ID is found through its VPC, even when the account has other gateways,
// including one that is not attached to any VPC.
func TestSharedEgressOnlyInternetGatewayFoundByVPC(t *testing.T) {
	ctx := context.TODO()

	cloud := awsup.BuildMockAWSCloud("us-east-1", "abc")
	c := &mockec2.MockEC2{}
	cloud.MockEC2 = c

	cidrs := []string{"172.20.0.0/16", "172.21.0.0/16"}
	var vpcIDs, eigwIDs []string
	for _, cidr := range cidrs {
		vpc, err := c.CreateVpc(ctx, &ec2.CreateVpcInput{
			CidrBlock: aws.String(cidr),
		})
		if err != nil {
			t.Fatalf("error creating test VPC: %v", err)
		}
		eigw, err := c.CreateEgressOnlyInternetGateway(ctx, &ec2.CreateEgressOnlyInternetGatewayInput{
			VpcId: vpc.Vpc.VpcId,
		})
		if err != nil {
			t.Fatalf("error creating test eigw: %v", err)
		}
		vpcIDs = append(vpcIDs, aws.ToString(vpc.Vpc.VpcId))
		eigwIDs = append(eigwIDs, aws.ToString(eigw.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId))
	}
	// A gateway with no attachment must be skipped.
	c.EgressOnlyInternetGateways["eigw-unattached"] = &ec2types.EgressOnlyInternetGateway{
		EgressOnlyInternetGatewayId: aws.String("eigw-unattached"),
	}
	// A gateway whose attachment is not in the attached state must be skipped.
	detachedVPC, err := c.CreateVpc(ctx, &ec2.CreateVpcInput{
		CidrBlock: aws.String("172.22.0.0/16"),
	})
	if err != nil {
		t.Fatalf("error creating test VPC: %v", err)
	}
	c.EgressOnlyInternetGateways["eigw-detached"] = &ec2types.EgressOnlyInternetGateway{
		EgressOnlyInternetGatewayId: aws.String("eigw-detached"),
		Attachments: []ec2types.InternetGatewayAttachment{
			{
				VpcId: detachedVPC.Vpc.VpcId,
				State: ec2types.AttachmentStatusDetached,
			},
		},
	}

	found, err := findEgressOnlyInternetGatewayForVPC(ctx, cloud, aws.ToString(detachedVPC.Vpc.VpcId))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("expected no EgressOnlyInternetGateway for VPC with a detached gateway, got %q", aws.ToString(found.EgressOnlyInternetGatewayId))
	}

	for i, vpcID := range vpcIDs {
		vpc := &VPC{
			Name:      s("vpc"),
			Lifecycle: fi.LifecycleSync,
			CIDR:      s(cidrs[i]),
			Tags:      map[string]string{"kubernetes.io/cluster/cluster.example.com": "shared"},
			Shared:    new(true),
			ID:        s(vpcID),
		}
		eigw := &EgressOnlyInternetGateway{
			Name:      s("eigw"),
			Lifecycle: fi.LifecycleSync,
			VPC:       vpc,
			Shared:    new(true),
			Tags:      make(map[string]string),
		}

		runTasks(t, cloud, map[string]fi.CloudupTask{"vpc": vpc, "eigw": eigw})

		if got := fi.ValueOf(eigw.ID); got != eigwIDs[i] {
			t.Errorf("expected EgressOnlyInternetGateway %q for VPC %q, got %q", eigwIDs[i], vpcID, got)
		}
	}

	if got := len(c.EgressOnlyInternetGatewayIds()); got != 4 {
		t.Errorf("expected 4 EgressOnlyInternetGateways, found %d: %v", got, c.EgressOnlyInternetGatewayIds())
	}
}

// TestSharedEgressOnlyInternetGatewayFoundByID checks that a shared EgressOnlyInternetGateway
// with a known ID and no VPC, as built for an additionalRoutes eigw- target, is found by its ID.
func TestSharedEgressOnlyInternetGatewayFoundByID(t *testing.T) {
	ctx := context.TODO()

	cloud := awsup.BuildMockAWSCloud("us-east-1", "abc")
	c := &mockec2.MockEC2{}
	cloud.MockEC2 = c

	vpc, err := c.CreateVpc(ctx, &ec2.CreateVpcInput{
		CidrBlock: aws.String("172.20.0.0/16"),
	})
	if err != nil {
		t.Fatalf("error creating test VPC: %v", err)
	}
	created, err := c.CreateEgressOnlyInternetGateway(ctx, &ec2.CreateEgressOnlyInternetGatewayInput{
		VpcId: vpc.Vpc.VpcId,
	})
	if err != nil {
		t.Fatalf("error creating test eigw: %v", err)
	}

	eigw := &EgressOnlyInternetGateway{
		Name:      created.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId,
		Lifecycle: fi.LifecycleSync,
		ID:        created.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId,
		Shared:    new(true),
	}

	runTasks(t, cloud, map[string]fi.CloudupTask{"eigw": eigw})
	checkNoChanges(t, ctx, cloud, map[string]fi.CloudupTask{"eigw": eigw})
}

func runTasks(t *testing.T, cloud awsup.AWSCloud, allTasks map[string]fi.CloudupTask) {
	t.Helper()
	ctx := context.TODO()

	target := &awsup.AWSAPITarget{
		Cloud: cloud,
	}

	context, err := fi.NewCloudupContext(ctx, fi.DeletionProcessingModeDeleteIncludingDeferred, target, nil, cloud, nil, nil, nil, allTasks)
	if err != nil {
		t.Fatalf("error building context: %v", err)
	}

	if err := context.RunTasks(testRunTasksOptions); err != nil {
		t.Fatalf("unexpected error during Run: %v", err)
	}
}
