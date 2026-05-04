// Copyright The Helm Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package helmstrvals is an in-tree copy of helm.sh/helm/v3/pkg/strvals at tag
// v3.19.4. It is forked rather than imported so kops does not pull in the
// helm module just for "--set k=v" parsing in `kops toolbox template`.
//
// Modifications relative to upstream:
//
//   - removed unused public APIs: Parse, ParseString, ToYAML, ParseFile,
//     ParseIntoFile, ParseJSON, ParseLiteralInto and the literal_parser
//     supporting them; only ParseInto and ParseIntoString are kept
//   - removed the JSON-value and file-value branches in (*parser).key and
//     (*parser).listItem along with the isjsonval field, newJSONParser,
//     newFileParser, RunesValueReader, and (*parser).emptyVal
//   - replaced the reader callback with an inlined typedVal call (the
//     callback existed only to dispatch between string and JSON/file
//     readers, which are no longer present)
//   - inlined the inMap helper as a direct map index in runesUntil
//   - github.com/pkg/errors replaced with stdlib errors and fmt.Errorf("%w")
package helmstrvals
