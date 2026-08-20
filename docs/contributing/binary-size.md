# Binary size

## Rules for contributors

* Never call `reflect.Value.Method(i)` or `reflect.Type.Method(i)`.
* Do not add `MethodByName` calls to non-test, non-vendored kOps code. The only existing calls, in `upup/pkg/fi/context.go` and `upup/pkg/fi/default_methods.go`, must keep string literals. Do not move the names into variables or loops.
* Do not make the standard library `text/template` or `html/template` executor reachable. Render templates with `third_party/forked/text/template`; it does not support calling methods on template data, so restructure the data instead.
* Do not call Cobra's `SetUsageTemplate`, `SetHelpTemplate` or `SetVersionTemplate`.
* Do not change the `scaleway-sdk-go` or `linodego` pins without comparing binary sizes.
* Pass `-tags=disable_grpc_modules,grpcnotrace` in every new shipped binary or image target and in scripts that call `go build` or `ko` directly.
* Keep large SDK clients out of structs reachable through interfaces or reflection. Do not add SDK clients to nodeup's `awsup.Cloud`.

## Why these rules matter

kOps ships the statically linked `kops`, `nodeup`, `channels`, `kops-controller`, `dns-controller`, `kube-apiserver-healthcheck` and `discovery-server` binaries. `nodeup` is downloaded on every node boot; most others are distributed to clusters as container images.

A series of changes cut these binaries to roughly half their previous size, mostly by preserving the Go linker's dead-code elimination. One innocent-looking change can add tens of megabytes to a binary.

### Dynamic method lookup disables method pruning

For a reachable `MethodByName` call with a non-constant argument, the compiler sets `REFLECTMETHOD`, a flag meaning it cannot determine the method name. The linker must then retain every exported method of every reachable type. This can add up to about 80MB to the largest binaries, including `kops` and `kops-controller`. See [golang/go#72895](https://github.com/golang/go/issues/72895).

With a compile-time string literal, the linker retains only methods with that name. The indexed `Method(i)` forms have no literal equivalent and always force full retention.

### Standard library templates use dynamic method lookup

The standard library `text/template` executor resolves `{{.Method}}` through dynamic method lookup. The kOps fork removes that behavior.

One reachable copy restores the full penalty, even through a dependency:

* Cobra imports `text/template`, but its executor is reachable only through `SetUsageTemplate`, `SetHelpTemplate` and `SetVersionTemplate`.
* `scaleway-sdk-go` is held at v1.0.0-beta.36 by a `go.mod` `replace` because v1.0.0-beta.37 builds SRN strings with `text/template`. `linodego` is pinned to a commit that removed template-based debug logging. Check sizes before changing either pin.

### The build tags remove unused code

Makefile targets for shipped binaries and images pass `disable_grpc_modules,grpcnotrace` through `BUILDTAGS`. `disable_grpc_modules` removes the unused GCS gRPC transport, saving about 12MB. `grpcnotrace` removes `golang.org/x/net/trace` from gRPC, saving about 21MB in some binaries. `x/net/trace` also uses `text/template`.

### SDK clients must stay out of reflection's reach

A type descriptor is runtime metadata for a Go type. Storing a large SDK client in an interface-held struct can make its descriptor reachable. Matching interface calls or reflection can then retain its exported methods.

nodeup uses the lean, concrete AWS cloud in `upup/pkg/fi/nodeup/awsup`, with SDK clients in unexported package state, instead of the full, interface-based `cloudup/awsup` cloud. Provider code needed only by nodes lives in leaf metadata packages such as `upup/pkg/fi/cloudup/*metadata`, so nodeup does not link entire cloud implementations.

## Guardrails

`golangci-lint` points violations to this page. `forbidigo` rejects indexed `Method` calls and `MethodByName` calls outside the two allowlisted files. Reviewers must still check that calls in those files use string literals.

`depguard` rejects direct imports of `text/template` and `html/template`. Its exceptions cover tests, `upup/tools/generators`, and the fork's `FuncMap` alias. It cannot catch an executor reached through a dependency.

## Investigating size changes

* Build without `-s -w`, then compare large symbols: `go tool nm -size -sort size <binary> | head -50`.
* Trace why the linker retains a symbol: `go build -ldflags=all=-dumpdep ...`. The output has one greppable `A -> B` dependency edge per line.
* If thousands of unused exported methods appear, such as every `ec2.Client` API method in nodeup, look for a reachable `REFLECTMETHOD` call or standard library template executor.
* See `third_party/forked/text/template/README.md` for the fork and its measured size changes.
