/*
Copyright 2026 The Kubernetes Authors.

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

package fi

import (
	"testing"
)

func TestECRRegistryRegion(t *testing.T) {
	grid := []struct {
		registry       string
		expectedRegion string
		expectError    bool
	}{
		{
			registry:       "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			expectedRegion: "us-east-1",
		},
		{
			registry:       "123456789012.dkr.ecr.eu-central-1.amazonaws.com",
			expectedRegion: "eu-central-1",
		},
		{
			registry:    "registry.example.com",
			expectError: true,
		},
	}

	for _, g := range grid {
		t.Run(g.registry, func(t *testing.T) {
			region, err := ecrRegistryRegion(g.registry)
			if g.expectError {
				if err == nil {
					t.Fatalf("expected an error, got region %q", region)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if region != g.expectedRegion {
				t.Errorf("unexpected region: expected %q, but got %q", g.expectedRegion, region)
			}
		})
	}
}

func TestParseBearerChallenge(t *testing.T) {
	grid := []struct {
		challenge       string
		expectedRealm   string
		expectedService string
		expectError     bool
	}{
		{
			challenge:       `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`,
			expectedRealm:   "https://auth.docker.io/token",
			expectedService: "registry.docker.io",
		},
		{
			challenge:       `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:owner/repo:pull"`,
			expectedRealm:   "https://ghcr.io/token",
			expectedService: "ghcr.io",
		},
		{
			challenge:     `Bearer realm="https://example.com/token"`,
			expectedRealm: "https://example.com/token",
		},
		{
			challenge:   `Basic realm="registry"`,
			expectError: true,
		},
		{
			challenge:   `Bearer service="example.com"`,
			expectError: true,
		},
		{
			challenge:   "",
			expectError: true,
		},
	}

	for _, g := range grid {
		t.Run(g.challenge, func(t *testing.T) {
			realm, service, err := parseBearerChallenge(g.challenge)
			if g.expectError {
				if err == nil {
					t.Fatalf("expected an error, got realm %q, service %q", realm, service)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if realm != g.expectedRealm {
				t.Errorf("unexpected realm: expected %q, but got %q", g.expectedRealm, realm)
			}
			if service != g.expectedService {
				t.Errorf("unexpected service: expected %q, but got %q", g.expectedService, service)
			}
		})
	}
}
