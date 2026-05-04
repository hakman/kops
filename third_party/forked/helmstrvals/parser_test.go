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

package helmstrvals

import (
	"reflect"
	"testing"
)

func TestParseInto(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]interface{}
	}{
		{
			name:  "scalar string",
			input: "foo=bar",
			want:  map[string]interface{}{"foo": "bar"},
		},
		{
			name:  "scalar int coerced",
			input: "foo=42",
			want:  map[string]interface{}{"foo": int64(42)},
		},
		{
			name:  "scalar bool coerced",
			input: "foo=true",
			want:  map[string]interface{}{"foo": true},
		},
		{
			name:  "scalar null coerced",
			input: "foo=null",
			want:  map[string]interface{}{"foo": nil},
		},
		{
			name:  "leading-zero stays string",
			input: "foo=0123",
			want:  map[string]interface{}{"foo": "0123"},
		},
		{
			name:  "nested key",
			input: "a.b.c=v",
			want: map[string]interface{}{
				"a": map[string]interface{}{
					"b": map[string]interface{}{"c": "v"},
				},
			},
		},
		{
			name:  "list literal",
			input: "fruits={apple,banana}",
			want:  map[string]interface{}{"fruits": []interface{}{"apple", "banana"}},
		},
		{
			name:  "list index",
			input: "items[0]=hi,items[1]=lo",
			want:  map[string]interface{}{"items": []interface{}{"hi", "lo"}},
		},
		{
			name:  "comma separated",
			input: "a=1,b=2",
			want:  map[string]interface{}{"a": int64(1), "b": int64(2)},
		},
		{
			name:  "escape comma",
			input: `foo=a\,b`,
			want:  map[string]interface{}{"foo": "a,b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]interface{}{}
			if err := ParseInto(tt.input, got); err != nil {
				t.Fatalf("ParseInto(%q) error: %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseInto(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseIntoString(t *testing.T) {
	got := map[string]interface{}{}
	if err := ParseIntoString("a=42,b=true", got); err != nil {
		t.Fatalf("ParseIntoString error: %v", err)
	}
	want := map[string]interface{}{"a": "42", "b": "true"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseIntoString = %#v, want %#v", got, want)
	}
}

func TestParseIntoOverwrites(t *testing.T) {
	dest := map[string]interface{}{"foo": "bar"}
	if err := ParseInto("foo=baz", dest); err != nil {
		t.Fatalf("ParseInto error: %v", err)
	}
	if dest["foo"] != "baz" {
		t.Errorf("got %v, want baz", dest["foo"])
	}
}

func TestParseIntoErrors(t *testing.T) {
	tests := []string{
		"foo",       // no value
		"foo=v,bar", // dangling key
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			if err := ParseInto(in, map[string]interface{}{}); err == nil {
				t.Errorf("ParseInto(%q) unexpectedly succeeded", in)
			}
		})
	}
}
