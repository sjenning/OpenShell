<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Protobuf API conventions

This directory defines OpenShell's gRPC contracts. These conventions are the
source of truth for public protobuf API design. Apply them to new APIs and when
changing existing APIs; generated SDK naming follows from these definitions.

## Entity references

- Use `name` for the primary resource targeted by an RPC.
- Use the resource's role for a related resource reference, such as `sandbox`,
  `provider`, `service`, or `rule`.
- Do not append `_name` to a canonical entity reference. Its value is already
  the canonical name. Descriptive values, local map keys, implementation
  labels, and configured registration names that are not entity references may
  retain the suffix. Examples include `display_name`, `file_name`,
  `driver_name`, `runtime_class_name`, `rule_name`, and `middleware_name`.
- Public callers reference entities by canonical name. Keep immutable IDs at
  authentication, persistence, compute-driver, and other internal boundaries.

For example:

```proto
message GetSandboxRequest {
  openshell.datamodel.v1.WorkspaceSelector workspace_scope = 2;
  string name = 1;
}

message ExposeServiceRequest {
  openshell.datamodel.v1.WorkspaceSelector workspace_scope = 5;
  string sandbox = 1;
  string name = 2;
}
```

`GetSandboxRequest.name` identifies the RPC's primary resource.
`ExposeServiceRequest.sandbox` identifies a related sandbox while `name`
identifies the service being exposed.

## Workspace scope

- Public workspace-scoped requests declare `workspace_scope` before every
  other field. Existing wire field numbers do not need to follow declaration
  order.
- Type `workspace_scope` as
  `openshell.datamodel.v1.WorkspaceSelector`.
- Requests operating in one workspace require a non-empty canonical
  `WorkspaceSelector.workspace`. The `default` workspace is an explicit name,
  not an omitted-value fallback.
- Accept `WorkspaceSelector.all_workspaces` only on collection-list RPCs that
  explicitly document and authorize cross-workspace access. The supported
  public collections are sandboxes, sandbox templates, providers, and
  services.
- Requests whose primary resource is a workspace use `name`, not
  `workspace_scope`.
- Document every request that permits an omitted selector. Current exceptions
  are platform provider-profile scope and authenticated sandbox bootstrap.

## Field and message design

- Prefer a dedicated request and response message for each RPC, including
  requests that are currently empty.
- Use `google.protobuf.Timestamp` for absolute time and
  `google.protobuf.Duration` for elapsed time.
- Use optional presence when omitted and explicitly empty values have different
  meanings. Do not infer presence from a protobuf scalar's default value.
- Keep public request fields in semantic reading order. Field numbers preserve
  wire identity and may therefore differ from declaration order.
- Document authorization-sensitive selector variants and omission semantics on
  the containing request.

## Schema evolution

- Treat field numbers and fully qualified message names as durable wire
  identities.
- When removing or renaming a field, reserve its old number and source name. Do
  not reuse either for a different meaning.
- Review changes against both the public descriptor closure and durable stored
  protobuf closure. The `public_and_durable_schema_inventories_are_complete`
  test in `openshell-server` owns both inventories.
- Regenerate Rust, Python, Go, and TypeScript bindings after contract changes.
  Run `mise run pre-commit`, the affected SDK checks, and relevant server tests
  before submitting the change.

## Supervisor host protocol

[`supervisor_host.proto`](supervisor_host.proto) is the private stream between
a gateway and the supervisor process it shares among its sandboxes: the
supervisor attaches, the gateway sends complete assignment snapshots, and the
supervisor reports what it hosts. It is a version-locked deployment protocol
served on the gateway listener but authorized only for the gateway-minted
supervisor token (`auth_mode: "supervisor"`). It is not imported by
`openshell.proto`, so SDK generation and
gRPC reflection exclude it; the server's schema inventory test classifies it
explicitly. `SandboxInstanceAssignment.launch_material` carries the existing
JSON sandbox instance registration of `openshell-supervisor-control` and is
marked secret.

## Credential issuer protocols

`credential_store.proto`, `credential_refresh.proto`, and `token_minter.proto`
define the private gateway-to-issuer and issuer-to-minter APIs. They are separate
from gateway RPCs and are not served on the gateway listener or exported by the
curated SDKs. Immutable IDs/references in these contracts identify internal
resources; supplied owner metadata never replaces mTLS caller authentication.
Secret-bearing fields carry the `secret` option, and Rust wire messages redact
secret-bearing debug output. Watches use durable namespace-scoped event cursors,
not per-reference value versions; reset events require complete reconciliation.
Value-free checkpoint frames advance replay progress, including filtered events,
but do not by themselves complete client reconciliation. Metadata inspection
returns versions, pending-value availability, expiration, and zero cache TTL
without backend value reads. Reserved outputs reject ordinary resolution until
first publication; reservations never stand in for fabricated secret values.
Capabilities advertise that support and message/batch limits. The additive
`ReserveSecret` capability allocates an immutable pending identity with a
value-free idempotency intent. A caller can journal the returned reference before
sending a conditional value fill, or replay allocation without retaining the
value. Original reservation receipts survive fill/deletion; tombstones fence
late fills rather than allowing resurrection.

The refresh catalog separately advertises pending grant reservations.
`ReserveGrant` allocates a grant epoch and fixed pending outputs without
configuration, refresh material, or backend values. The gateway journals those
identities before sending inputs to `InitializeGrant`. Initialization encrypts
inputs and atomically commits the one-time transition to a mintable pending
grant with its replay receipt. Reserved grants cannot mint; deletion fences late
initialization. Exact reservation/initialization receipts remain replayable after
deletion and never resurrect a grant. Neither operation retries an upstream mint.

The issuer library hosts authenticated store, refresh, and custom-minter
services. These contracts do not enable a gateway remote-source mode or relax
authorization for an existing gateway RPC; deployment and gateway wiring remain
separate.

## Isolation backend protocol

[`isolation_backend.proto`](isolation_backend.proto) defines backend discovery,
boundary binding, and optional suspend/resume RPCs.
[`sandbox_protocol.proto`](sandbox_protocol.proto) defines typed workload
control, process I/O, and network mediation over the bound boundary. Both are
supervisor-to-backend contracts, not gateway RPCs. Backend authors can generate bindings independently
from these definitions. The negotiated Sandbox Protocol version covers the gRPC
services, typed messages, streaming, and lifecycle semantics.
