# Cross-cluster credential issuer deployment E2E

This opt-in feature suite deploys the real gateway chart in one Kubernetes
cluster and the real credential issuer chart in another. A small test-only
`TokenMinter` service in the issuer cluster uses the production private protocol,
`ExtensionTlsAcceptor`, and `IssuerPolicy`. It is not a mock credential issuer.
Gateway → issuer and issuer → minter both require private-CA mTLS, with distinct
SPIFFE client identities and independent authorization. The public gateway also
requires mTLS. All credentials and certificates in this lane are synthetic.

The tests use the existing `#[testkit::test]` framework, installed candidate CLI,
and Rust SDK. They do not implement another test runner. There are no ignored
tests or environment-driven successful skips: missing setup fails explicitly.
Do not run this suite as part of an unconfigured `cargo test --workspace`.

## Coverage

`cross_cluster_public_lifecycle_and_live_supervisor` drives public APIs:

- Import a provider profile, create a provider, and configure `custom:e2e` refresh.
  The minter descriptor, not a caller's optional hint, classifies secret material.
- Rotate, read refresh status/history, and export a value with issuer-owned expiry.
- Create a real sandbox using the chart's shared gateway-topology supervisor.
  Sandbox creation also exercises issuer-backed SSH identity and supervisor launch
  material. Its long-running main process retains
  its original credential placeholder. Each resource request comes from a child
  of that process, not a fresh exec environment. The upstream invalidates every
  prior minted token; a stale supervisor snapshot cannot pass after rotation.
- Stop the issuer Deployment while leaving its durable SQLite PVC, minter,
  resource server, gateway, supervisor and workload alive. Public export must
  fail, and the running process must lose resource access after watch loss.
- Restart the issuer and require the *same durable value* and retained-handle
  access to recover before any new rotate call. This exercises watch reconnect,
  reset and reconciliation instead of masking recovery with a mutation.
- Rotate again, verify delivery and unchanged workload PID, reconfigure refresh,
  and verify that the old authorization-epoch placeholder is denied.
- Delete refresh through the public API, verify preservation of the published
  output as static credentials, delete the provider, and deny subsequent export.

`mtls_identity_workspace_and_minter_access_denial` also uses real networked
private RPCs to verify that a client without a certificate is rejected, a trusted
but unbound gateway identity is denied,
an authorized gateway cannot access an unbound workspace or another gateway's
reference, and a gateway certificate cannot impersonate the issuer at the minter.

The issuer's and gateway's databases are separate. Nothing is delivered directly
from the issuer to supervisors. Supplemental private-RPC denial probes never
replace the public provider workflow.

## Safety boundary

- **Never target the currently selected cluster.** The runner reads the selected
  cluster in the normal user kubeconfig, the ambient `KUBECONFIG`, and an explicit
  E2E kubeconfig. It compares physical `kube-system` UIDs, so context aliases
  cannot bypass this guard. If it cannot identify a selected cluster, it fails
  closed. It never runs `use-context`, edits a kubeconfig, or selects a gateway
  in the user's OpenShell configuration.
- External mode requires two explicit contexts in one dedicated kubeconfig and
  two **absent** namespaces prefixed `issuer-e2e-`. It refuses existing namespaces,
  even if a prior run created them. It creates and cleans up only its own resources.
- Kind mode creates two uniquely named disposable clusters using a temporary
  kubeconfig. It reuses the repository's pinned Agent Sandbox installer only on
  its newly created gateway cluster. Existing-context mode never installs or
  upgrades cluster prerequisites.
- The product issuer Service remains ClusterIP. A test-owned raw TCP NodePort
  routes cross-cluster traffic without terminating TLS. The issuer node's IPv4
  address must be private RFC1918/RFC6598 and directly routable from the gateway
  cluster **and test host**. Firewalls must not expose fixture NodePorts publicly.
  Issuer NetworkPolicy permits private routed CIDRs; exact mTLS identities and
  workspace bindings remain required. This lane does not claim to verify CNI
  NetworkPolicy enforcement; kind's default CNI does not enforce it.
- CLI/SDK configuration, CA keys, certificates, KEK, and issuer TOML live in a
  mode-0700 temporary directory and Kubernetes Secrets. Cleanup removes them.
  No real operator credentials or provider tokens are used or exported.

## Prerequisites

- Linux for local kind mode: its two Docker-backed clusters use directly routed
  container NodeIPs. Docker Desktop's VM usually does not expose these NodeIPs
  to the host; use explicitly routed external contexts on other hosts.
- Running Docker and an existing `kind` executable for kind mode. The task does
  not install kind, build images, or use a pre-existing kind cluster implicitly.
- `mise install`, Rust toolchain, Cargo, `kubectl`, Helm, `jq`, `openssl`, `base64`.
  Image builds also require the repository's normal zigbuild/C toolchain.
- Matching candidate gateway, issuer, sandbox runtime and supervisor images,
  the custom-minter fixture image, and candidate `openshell` CLI.
- A default dynamic block-backed StorageClass in each cluster. The gateway,
  sandbox workspace, and issuer use fresh PVCs. Existing-context mode also needs
  a supported Agent Sandbox CRD/controller on the gateway cluster (the maintained
  installer defaults to `v1.0.3`). Install that prerequisite separately and only
  on a cluster you own; the lane will not mutate cluster-wide prerequisites there.
- Kubernetes permission to create namespaces, their contents and the gateway
  chart's namespace-specific ClusterRole/ClusterRoleBinding. Cleanup uninstalls
  the chart before deleting namespaces so cluster-scoped gateway RBAC is removed.
- Cluster/node egress to fetch the pinned Agent Sandbox release/controller,
  `nvcr.io/nvidia/base/ubuntu:24.04` (contains Python 3), and the chart's pinned
  BusyBox key-preparation image, or operator-preloaded equivalents. Candidate
  images must already be local for kind, or pullable by external cluster nodes.
- External mode additionally needs private routing to an issuer node and free
  NodePorts 30443 (issuer mTLS), 30444 (minter mTLS denial probe), and 30080
  (synthetic resource HTTP). Override these with `OPENSHELL_ISSUER_E2E_ISSUER_PORT`,
  `OPENSHELL_ISSUER_E2E_MINTER_PORT`, and `OPENSHELL_ISSUER_E2E_RESOURCE_PORT`.

The selected external/user cluster is not a prerequisite and must not be used.

## Build candidates, then run isolated kind

Run builds serially before starting the lane. The image task includes the fixture
binary and its pinned runtime image, and does not publish images:

```shell
IMAGE_TAG=dev mise run e2e:credential-issuer:images
cargo build -p openshell-cli
```

If dependencies changed, update the feature workspace lockfile without upgrading
unrelated packages, then verify alignment with the root lockfile:

```shell
cargo metadata --format-version 1 --manifest-path tests/suites/features/Cargo.toml > /dev/null
uv run tasks/scripts/check_cargo_lockfile_alignment.py
```

Set the exact candidate inputs (the defaults below match the local image task):

```shell
export OPENSHELL_BIN="$PWD/target/debug/openshell"
export OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE=openshell/gateway:dev
export OPENSHELL_ISSUER_E2E_SUPERVISOR_IMAGE=openshell/supervisor:dev
export OPENSHELL_ISSUER_E2E_SANDBOX_IMAGE=openshell/sandbox:dev
export OPENSHELL_ISSUER_E2E_ISSUER_IMAGE=openshell/credential-issuer:dev
export OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE=openshell/credential-issuer-e2e-fixture:dev
mise run e2e:credential-issuer:kind
```

The suite defaults to push delivery. Repeat on a fresh pair of clusters with
`OPENSHELL_ISSUER_E2E_DELIVERY_MODE=poll` to cover polling delivery:

```shell
OPENSHELL_ISSUER_E2E_DELIVERY_MODE=poll mise run e2e:credential-issuer:kind
```

The script creates/deletes only its generated kind cluster names and never
merges them into `~/.kube/config` or the checkout's `kubeconfig`.

## Two existing, explicitly authorized clusters

Use the candidate inputs above, selecting image references available to those
clusters. Supply a dedicated kubeconfig containing both contexts. Its
`current-context` must be unset or select a third, non-target cluster; the normal
user/ambient kubeconfig may keep selecting the user's unrelated cluster. Do not
change the user's selected context to bypass the guard.

```shell
export OPENSHELL_ISSUER_E2E_KUBECONFIG=/secure/test-clusters.kubeconfig
export OPENSHELL_ISSUER_E2E_GATEWAY_CONTEXT=dedicated-e2e-gateway
export OPENSHELL_ISSUER_E2E_ISSUER_CONTEXT=dedicated-e2e-security
export OPENSHELL_ISSUER_E2E_GATEWAY_NAMESPACE=issuer-e2e-gateway-run1
export OPENSHELL_ISSUER_E2E_ISSUER_NAMESPACE=issuer-e2e-security-run1
export OPENSHELL_ISSUER_E2E_ISSUER_ADDRESS=10.20.30.40
mise run e2e:credential-issuer:preflight
mise run e2e:credential-issuer
```

`preflight` is read-only: it verifies the two physical cluster identities,
selected-cluster exclusions, namespace absence, explicit image inputs, private
address/ports, and the gateway CRD. It does not test network reachability, image
pull access, StorageClass provisioning or application readiness. A successful
preflight is not a successful E2E run.

## Evidence and lightweight checks

Each run writes `results/credential-issuer/<UTC-run>/topology.json`, test output,
Pod lists/events, bounded issuer/gateway logs, and cleanup diagnostics. Override
the parent directory with `OPENSHELL_ISSUER_E2E_RESULTS`. Topology evidence records
both physical cluster UIDs. No Secret dumps, full ConfigMaps, TOML, mounted files,
or Pod `describe`/environment output are collected. The fixture never logs tokens.
Both tests must pass; setup failure or test failure returns nonzero and still
runs cleanup. The temporary CA material is never copied into evidence.

Run the isolation/input guard regressions without Cargo, Docker, or any cluster:

```shell
mise run test:credential-issuer-e2e-runner
bash -n tasks/scripts/test-credential-issuer-e2e.sh
rustfmt --edition 2024 --check tests/suites/features/credential-issuer/src/fixture.rs tests/suites/features/credential-issuer/tests/remote.rs
```

The shell test replaces `kubectl` with a fail-closed fake and checks both context
aliases and physical-cluster collisions, refusal to reuse namespaces, unreachable
selected-cluster failures, and missing/unsafe inputs. Fake kind/Docker commands
also simulate partial failure on either cluster creation: cleanup must delete
exactly the generated cluster names using the temporary kubeconfig, preserve
preexisting clusters and operator kubeconfigs, and never invoke Cargo. These
checks do not replace building the fixture/test crate and running the deployment
lane.
