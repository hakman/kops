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

// Adapted from k8s.io/cloud-provider-aws cmd/ecr-credential-provider (v1.31.7),
// trimmed to the private ECR flow that the kOps-generated credential provider
// config uses (no public ECR, no service account token exchange).

package credentialprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

var ecrPrivateHostPattern = regexp.MustCompile(`^(\d{12})\.dkr[\.\-]ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(?:\.cn)?|on\.(?:aws|amazonwebservices\.com\.cn)|sc2s\.sgov\.gov|c2s\.ic\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)$`)

// ECR abstracts the calls we make to aws-sdk for testing purposes
type ECR interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// ECRProvider fetches credentials for private ECR registries.
type ECRProvider struct {
	ecr ECR
}

// NewECRProvider returns an ECRProvider that lazily builds its ECR client
// from the image's registry region, falling back to the default AWS config
// (in particular the AWS_REGION environment variable set in the kubelet
// credential provider config).
func NewECRProvider() *ECRProvider {
	return &ECRProvider{}
}

func defaultECRClient(ctx context.Context, region string) (ECR, error) {
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
		)
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		return nil, err
	}

	return ecr.NewFromConfig(cfg), nil
}

// GetCredentials implements Provider.
func (e *ECRProvider) GetCredentials(ctx context.Context, image string) (*v1.CredentialProviderResponse, error) {
	imageHost, err := parseHostFromImageReference(image)
	if err != nil {
		return nil, err
	}

	if e.ecr == nil {
		region := parseRegionFromECRPrivateHost(imageHost)
		e.ecr, err = defaultECRClient(ctx, region)
		if err != nil {
			return nil, err
		}
	}

	output, err := e.ecr.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, errors.New("response output from ECR was nil")
	}
	if len(output.AuthorizationData) == 0 {
		return nil, errors.New("authorization data was empty")
	}

	authToken := output.AuthorizationData[0].AuthorizationToken
	if authToken == nil {
		return nil, errors.New("authorization token in response was nil")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(aws.ToString(authToken))
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("error parsing username and password from authorization token")
	}

	return &v1.CredentialProviderResponse{
		CacheKeyType:  v1.RegistryPluginCacheKeyType,
		CacheDuration: getCacheDuration(output.AuthorizationData[0].ExpiresAt),
		Auth: map[string]v1.AuthConfig{
			imageHost: {
				Username: parts[0],
				Password: parts[1],
			},
		},
	}, nil
}

// getCacheDuration calculates the credentials cache duration based on the ExpiresAt time from the authorization data
func getCacheDuration(expiresAt *time.Time) *metav1.Duration {
	var cacheDuration *metav1.Duration
	if expiresAt == nil {
		// explicitly set cache duration to 0 if expiresAt was nil so that
		// kubelet does not cache it in-memory
		cacheDuration = &metav1.Duration{Duration: 0}
	} else {
		// halving duration in order to compensate for the time loss between
		// the token creation and passing it all the way to kubelet.
		duration := time.Second * time.Duration((expiresAt.Unix()-time.Now().Unix())/2)
		if duration > 0 {
			cacheDuration = &metav1.Duration{Duration: duration}
		}
	}
	return cacheDuration
}

// parseHostFromImageReference parses the hostname from an image reference
func parseHostFromImageReference(image string) (string, error) {
	// a URL needs a scheme to be parsed correctly
	if !strings.Contains(image, "://") {
		image = "https://" + image
	}
	parsed, err := url.Parse(image)
	if err != nil {
		return "", fmt.Errorf("error parsing image reference %s: %v", image, err)
	}
	return parsed.Hostname(), nil
}

func parseRegionFromECRPrivateHost(host string) string {
	splitHost := ecrPrivateHostPattern.FindStringSubmatch(host)
	if len(splitHost) != 5 {
		return ""
	}
	return splitHost[3]
}
