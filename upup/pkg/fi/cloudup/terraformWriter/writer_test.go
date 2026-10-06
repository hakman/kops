/*
Copyright 2021 The Kubernetes Authors.

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

package terraformWriter

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOutputs(t *testing.T) {
	cases := []struct {
		name        string
		values      map[string]*terraformOutputVariable
		expected    map[string]OutputValue
		errExpected bool
	}{
		{
			name: "empty map",
		},
		{
			name: "single output",
			values: map[string]*terraformOutputVariable{
				"keyOne": {
					Key:   "key1",
					Value: LiteralFromStringValue("value1"),
				},
			},
			expected: map[string]OutputValue{
				"key1": {
					Value: LiteralFromStringValue("value1"),
				},
			},
		},
		{
			name: "list output",
			values: map[string]*terraformOutputVariable{
				"keyOne": {
					Key: "key1",
					ValueArray: []*Literal{
						LiteralFromStringValue("value2"),
						LiteralFromStringValue("value1"),
					},
				},
			},
			expected: map[string]OutputValue{
				"key1": {
					ValueArray: []*Literal{
						LiteralFromStringValue("value1"),
						LiteralFromStringValue("value2"),
					},
				},
			},
		},
		{
			name: "duplicate names",
			values: map[string]*terraformOutputVariable{
				"key.1": {
					Key:   "key.1",
					Value: LiteralFromStringValue("value1"),
				},
				"key-1": {
					Key:   "key-1",
					Value: LiteralFromStringValue("value2"),
				},
			},
			errExpected: true,
		},
		{
			name: "duplicate values",
			values: map[string]*terraformOutputVariable{
				"keyOne": {
					Key: "key1",
					ValueArray: []*Literal{
						LiteralFromStringValue("value1"),
						LiteralFromStringValue("value1"),
						LiteralFromStringValue("value2"),
					},
				},
			},
			expected: map[string]OutputValue{
				"key1": {
					ValueArray: []*Literal{
						LiteralFromStringValue("value1"),
						LiteralFromStringValue("value2"),
					},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := TerraformWriter{
				outputs: tc.values,
			}
			actual, err := target.GetOutputs()
			if tc.errExpected {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.ObjectsAreEqual(tc.expected, actual)
		})
	}
}

// TestHasProviderConcurrent checks that HasProvider can be called while other
// goroutines register providers, as happens when tasks render concurrently.
// Run with -race to detect unsynchronised access to Providers.
func TestHasProviderConcurrent(t *testing.T) {
	w := &TerraformWriter{}
	w.InitTerraformWriter()

	assert.False(t, w.HasProvider("aws"))

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			w.EnsureTerraformProvider("aws", map[string]string{"region": "us-test-1"})
		}()
		go func() {
			defer wg.Done()
			w.HasProvider("azurerm")
		}()
	}
	wg.Wait()

	assert.True(t, w.HasProvider("aws"))
	assert.False(t, w.HasProvider("azurerm"))
}
