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

package wellknownservices

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"

	"k8s.io/kops/pkg/apis/kops"
)

// WellKnownServiceIP returns the IP address at offset id within the cluster's
// ServiceClusterIPRange, e.g. id=1 for the kubernetes service, id=10 for kube-dns.
// It lives in this leaf package so that nodeup can compute service IPs without
// linking the full cloudup component model.
func WellKnownServiceIP(networkingSpec *kops.NetworkingSpec, id int) (net.IP, error) {
	_, cidr, err := net.ParseCIDR(networkingSpec.ServiceClusterIPRange)
	if err != nil {
		return nil, fmt.Errorf("error parsing ServiceClusterIPRange %q: %v", networkingSpec.ServiceClusterIPRange, err)
	}

	ip4 := cidr.IP.To4()
	if ip4 != nil {
		n := binary.BigEndian.Uint32(ip4)
		n += uint32(id)
		serviceIP := make(net.IP, len(ip4))
		binary.BigEndian.PutUint32(serviceIP, n)
		return serviceIP, nil
	}

	ip6 := cidr.IP.To16()
	if ip6 != nil {
		baseIPInt := big.NewInt(0)
		baseIPInt.SetBytes(ip6)
		serviceIPInt := big.NewInt(0)
		serviceIPInt.Add(big.NewInt(int64(id)), baseIPInt)
		serviceIP := make(net.IP, len(ip6))
		serviceIPBytes := serviceIPInt.Bytes()
		for i := range serviceIPBytes {
			serviceIP[len(serviceIP)-len(serviceIPBytes)+i] = serviceIPBytes[i]
		}
		return serviceIP, nil
	}

	return nil, fmt.Errorf("unexpected IP address type for ServiceClusterIPRange: %s", networkingSpec.ServiceClusterIPRange)
}
