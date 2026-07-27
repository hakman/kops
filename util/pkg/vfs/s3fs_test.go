/*
Copyright 2019 The Kubernetes Authors.

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

package vfs

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

func Test_S3Path_Parse(t *testing.T) {
	grid := []struct {
		Input          string
		ExpectError    bool
		ExpectedBucket string
		ExpectedPath   string
	}{
		{
			Input:          "s3://bucket",
			ExpectedBucket: "bucket",
			ExpectedPath:   "",
		},
		{
			Input:          "s3://bucket/path",
			ExpectedBucket: "bucket",
			ExpectedPath:   "path",
		},
		{
			Input:          "s3://bucket2/path/subpath",
			ExpectedBucket: "bucket2",
			ExpectedPath:   "path/subpath",
		},
		{
			Input:       "s3:///bucket/path/subpath",
			ExpectError: true,
		},
	}
	for _, g := range grid {
		s3path, err := Context.buildS3Path(g.Input)
		if !g.ExpectError {
			if err != nil {
				t.Fatalf("unexpected error parsing s3 path: %v", err)
			}
			if s3path.scheme != "s3" {
				t.Fatalf("unexpected scheme for s3 path, got %q expected \"s3\": %v", s3path.scheme, s3path)
			}
			if s3path.bucket != g.ExpectedBucket {
				t.Fatalf("unexpected s3 path: %v", s3path)
			}
			if s3path.key != g.ExpectedPath {
				t.Fatalf("unexpected s3 path: %v", s3path)
			}
		} else {
			if err == nil {
				t.Fatalf("unexpected error parsing %q", g.Input)
			}
		}
	}
}

func Test_LinodePath_Parse(t *testing.T) {
	grid := []struct {
		Input          string
		ExpectError    bool
		ExpectedBucket string
		ExpectedPath   string
	}{
		{
			Input:          "linode://bucket",
			ExpectedBucket: "bucket",
			ExpectedPath:   "",
		},
		{
			Input:          "linode://bucket/path",
			ExpectedBucket: "bucket",
			ExpectedPath:   "path",
		},
		{
			Input:          "linode://bucket2/path/subpath",
			ExpectedBucket: "bucket2",
			ExpectedPath:   "path/subpath",
		},
		{
			Input:       "linode:///bucket/path/subpath",
			ExpectError: true,
		},
	}
	for _, g := range grid {
		t.Setenv("S3_ENDPOINT", "https://example.com")
		s3path, err := Context.buildLinodePath(g.Input)
		if !g.ExpectError {
			if err != nil {
				t.Fatalf("unexpected error parsing linode path: %v", err)
			}
			if s3path.scheme != "linode" {
				t.Fatalf("expected scheme=\"linode\" for linode path, got %q: %v", s3path.scheme, s3path)
			}
			if s3path.bucket != g.ExpectedBucket {
				t.Fatalf("unexpected linode path: %v", s3path)
			}
			if s3path.key != g.ExpectedPath {
				t.Fatalf("unexpected linode path: %v", s3path)
			}
		} else {
			if err == nil {
				t.Fatalf("unexpected error parsing %q", g.Input)
			}
		}
	}
}

func Test_NonLinodeObjectStoragePaths_HaveCorrectScheme(t *testing.T) {
	grid := []struct {
		name   string
		input  string
		scheme string
		build  func(string) (*S3Path, error)
	}{
		{name: "do", input: "do://bucket/path", scheme: "do", build: Context.buildDOPath},
		{name: "hos", input: "hos://bucket/path", scheme: "hos", build: Context.buildHetznerPath},
		{name: "scw", input: "scw://bucket/path", scheme: "scw", build: Context.buildSCWPath},
	}

	for _, tc := range grid {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("S3_ENDPOINT", "https://example.com")
			s3path, err := tc.build(tc.input)
			if err != nil {
				t.Fatalf("unexpected error parsing %s path: %v", tc.name, err)
			}
			if s3path.scheme != tc.scheme {
				t.Fatalf("unexpected scheme for %s path, got %q expected %q", tc.name, s3path.scheme, tc.scheme)
			}
		})
	}
}

type fakeS3BucketAPI struct {
	policyStatus    *s3.GetBucketPolicyStatusOutput
	policyStatusErr error
	ownership       *s3.GetBucketOwnershipControlsOutput
	ownershipErr    error
}

func (f *fakeS3BucketAPI) GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	return f.policyStatus, f.policyStatusErr
}

func (f *fakeS3BucketAPI) GetBucketOwnershipControls(ctx context.Context, params *s3.GetBucketOwnershipControlsInput, optFns ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	return f.ownership, f.ownershipErr
}

func policyStatusOutput(isPublic bool) *s3.GetBucketPolicyStatusOutput {
	return &s3.GetBucketPolicyStatusOutput{
		PolicyStatus: &types.PolicyStatus{IsPublic: aws.Bool(isPublic)},
	}
}

func ownershipOutput(ownership types.ObjectOwnership) *s3.GetBucketOwnershipControlsOutput {
	return &s3.GetBucketOwnershipControlsOutput{
		OwnershipControls: &types.OwnershipControls{
			Rules: []types.OwnershipControlsRule{{ObjectOwnership: ownership}},
		},
	}
}

func TestIsBucketPublic(t *testing.T) {
	grid := []struct {
		name         string
		client       *fakeS3BucketAPI
		expectPublic bool
		expectError  bool
	}{
		{
			name: "no bucket policy",
			client: &fakeS3BucketAPI{
				policyStatusErr: &smithy.GenericAPIError{Code: "NoSuchBucketPolicy"},
			},
			expectPublic: false,
		},
		{
			name: "policy status error",
			client: &fakeS3BucketAPI{
				policyStatusErr: &smithy.GenericAPIError{Code: "AccessDenied"},
			},
			expectError: true,
		},
		{
			name: "policy not public",
			client: &fakeS3BucketAPI{
				policyStatus: policyStatusOutput(false),
			},
			expectPublic: false,
		},
		{
			name: "public policy with ACLs disabled",
			client: &fakeS3BucketAPI{
				policyStatus: policyStatusOutput(true),
				ownership:    ownershipOutput(types.ObjectOwnershipBucketOwnerEnforced),
			},
			expectPublic: true,
		},
		{
			// ACLs enabled only triggers a warning; the bucket is still considered public.
			name: "public policy with ACLs enabled",
			client: &fakeS3BucketAPI{
				policyStatus: policyStatusOutput(true),
				ownership:    ownershipOutput(types.ObjectOwnershipBucketOwnerPreferred),
			},
			expectPublic: true,
		},
		{
			// The ownership check is best-effort; an error there is not fatal.
			name: "public policy with ownership controls error",
			client: &fakeS3BucketAPI{
				policyStatus: policyStatusOutput(true),
				ownershipErr: &smithy.GenericAPIError{Code: "AccessDenied"},
			},
			expectPublic: true,
		},
	}
	for _, g := range grid {
		t.Run(g.name, func(t *testing.T) {
			public, err := isBucketPublic(context.Background(), g.client, "bucket")
			if g.expectError {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if public != g.expectPublic {
				t.Fatalf("expected public=%v, got %v", g.expectPublic, public)
			}
		})
	}
}

func TestBucketUsesACLs(t *testing.T) {
	grid := []struct {
		name           string
		client         *fakeS3BucketAPI
		expectUsesACLs bool
		expectError    bool
	}{
		{
			name: "bucket owner enforced",
			client: &fakeS3BucketAPI{
				ownership: ownershipOutput(types.ObjectOwnershipBucketOwnerEnforced),
			},
			expectUsesACLs: false,
		},
		{
			name: "bucket owner preferred",
			client: &fakeS3BucketAPI{
				ownership: ownershipOutput(types.ObjectOwnershipBucketOwnerPreferred),
			},
			expectUsesACLs: true,
		},
		{
			name: "object writer",
			client: &fakeS3BucketAPI{
				ownership: ownershipOutput(types.ObjectOwnershipObjectWriter),
			},
			expectUsesACLs: true,
		},
		{
			name: "mixed ownership rules",
			client: &fakeS3BucketAPI{
				ownership: &s3.GetBucketOwnershipControlsOutput{
					OwnershipControls: &types.OwnershipControls{
						Rules: []types.OwnershipControlsRule{
							{ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced},
							{ObjectOwnership: types.ObjectOwnershipObjectWriter},
						},
					},
				},
			},
			expectUsesACLs: true,
		},
		{
			name: "empty ownership rules",
			client: &fakeS3BucketAPI{
				ownership: &s3.GetBucketOwnershipControlsOutput{
					OwnershipControls: &types.OwnershipControls{},
				},
			},
			expectUsesACLs: true,
		},
		{
			name: "no ownership controls",
			client: &fakeS3BucketAPI{
				ownershipErr: &smithy.GenericAPIError{Code: "OwnershipControlsNotFoundError"},
			},
			expectUsesACLs: true,
		},
		{
			name: "ownership controls error",
			client: &fakeS3BucketAPI{
				ownershipErr: &smithy.GenericAPIError{Code: "AccessDenied"},
			},
			expectError: true,
		},
	}
	for _, g := range grid {
		t.Run(g.name, func(t *testing.T) {
			usesACLs, err := bucketUsesACLs(context.Background(), g.client, "bucket")
			if g.expectError {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if usesACLs != g.expectUsesACLs {
				t.Fatalf("expected usesACLs=%v, got %v", g.expectUsesACLs, usesACLs)
			}
		})
	}
}

func TestGetHTTPsUrl(t *testing.T) {
	grid := []struct {
		Path        string
		Dualstack   bool
		Region      string
		ExpectedURL string
	}{
		{
			Path:        "s3://bucket",
			Region:      "us-east-1",
			ExpectedURL: "https://bucket.s3.us-east-1.amazonaws.com",
		},
		{
			Path:        "s3://bucket.with.forced.path.style/subpath",
			Region:      "us-east-1",
			ExpectedURL: "https://s3.us-east-1.amazonaws.com/bucket.with.forced.path.style/subpath",
		},
		{
			Path:        "s3://bucket/path",
			Region:      "us-east-2",
			ExpectedURL: "https://bucket.s3.us-east-2.amazonaws.com/path",
		},
		{
			Path:        "s3://bucket2/path/subpath",
			Region:      "us-east-1",
			ExpectedURL: "https://bucket2.s3.us-east-1.amazonaws.com/path/subpath",
		},
		{
			Path:        "s3://bucket2-ds/path/subpath",
			Dualstack:   true,
			Region:      "us-east-1",
			ExpectedURL: "https://bucket2-ds.s3.dualstack.us-east-1.amazonaws.com/path/subpath",
		},
		{
			Path:        "s3://bucket2-cn/path/subpath",
			Region:      "cn-north-1",
			ExpectedURL: "https://bucket2-cn.s3.cn-north-1.amazonaws.com.cn/path/subpath",
		},
		{
			Path:        "s3://bucket2-cn-ds/path/subpath",
			Dualstack:   true,
			Region:      "cn-north-1",
			ExpectedURL: "https://bucket2-cn-ds.s3.dualstack.cn-north-1.amazonaws.com.cn/path/subpath",
		},
		{
			Path:        "s3://bucket2-gov/path/subpath",
			Region:      "us-gov-west-1",
			ExpectedURL: "https://bucket2-gov.s3.us-gov-west-1.amazonaws.com/path/subpath",
		},
		{
			Path:        "s3://bucket2-gov-ds/path/subpath",
			Dualstack:   true,
			Region:      "us-gov-west-1",
			ExpectedURL: "https://bucket2-gov-ds.s3.dualstack.us-gov-west-1.amazonaws.com/path/subpath",
		},
	}
	for _, g := range grid {
		t.Run(g.Path, func(t *testing.T) {
			// Must be nonempty in order to force S3_REGION usage
			// rather than querying S3 for the region.
			t.Setenv("S3_ENDPOINT", "1")
			t.Setenv("S3_REGION", g.Region)
			s3path, _ := Context.buildS3Path(g.Path)
			url, err := s3path.GetHTTPsUrl(g.Dualstack)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if url != g.ExpectedURL {
				t.Fatalf("expected url: %v vs actual url: %v", g.ExpectedURL, url)
			}
		})
	}
}
