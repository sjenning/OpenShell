<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell gateway server

The server owns control-plane RPCs, authentication, provider credential delivery,
and sandbox lifecycle orchestration. The `openshell-gateway` crate composes the
server with selected compute drivers.

## Sandbox launch identity

A new start, including an automatic restart, commits a fresh runtime generation
and an incremented authorization epoch before invoking the compute driver.
The launch session ID is derived from the durable sandbox ID and generation.
Retries reuse that generation and session, including after gateway restart.
Credential renewal retains both; credentials for an older launch cannot
authorize the new one.

## Shared supervisor pool

The `SharedSupervision` the gateway hands a compute driver that asks for it
always coordinates a pool of shared supervisor hosts, at any member count; the
driver itself is unchanged. `[openshell.gateway.supervisor_pool]` only tunes it
(`recovery_timeout_secs`), and the gateway refuses the table when no in-process
driver uses the shared supervisor. `supervisor_pool` keeps the
pool's durable state and reconciles it every two seconds on every gateway
replica, independent of which replica runs the compute driver's watch:

- **Membership.** The replica serving a member's host stream refreshes its
  `supervisor_pool_member` record from a task of its own, every two seconds and
  at once when a member attaches, leaves, or detaches, each write bounded, so a
  slow reconciliation pass never lets a served member expire. Only the member's
  newest stream (by accept time) writes the record, so a replica still holding
  a stale stream of the same process cannot overwrite it. A record older than 15
  seconds is dead; a member that announces it is leaving drops out at once; a
  member whose process changed lost every instance its previous process owned.
  The timings members and replicas share, and the reconnect budget that keeps a
  member reconnecting past an unresponsive replica well inside the TTL, are in
  `openshell_supervisor_control::pool_timing`.
- **Listings.** A pass reads each record type page by page after an immutable
  key (`list_by_type_after`), so a row removed meanwhile shifts nothing out of
  the listing. A listing is still not a snapshot, so before a pass drops an
  owner its previous view had, or an instance that view or an owner names, it
  reads the record by key; a failed read fails the pass, which then publishes
  nothing.
- **Desired set.** A launch records the instance (`supervisor_instance_assignment`)
  before anything else. The record holds only the handle of the launch
  material, which the configured credential store keeps, as it keeps sandbox SSH
  host keys. Every replica derives the desired set from these records and loads
  the material of instances owned by members it serves. Recording takes single
  atomic store writes and holds no lock: it reserves the route with a row named
  by the route and identified by a fresh writer token, stores the material, has
  a `supervisor_instance_material_candidate` row own the handle, and publishes
  by advancing exactly its reservation's version. A launch publishes its
  record as `Admitting`, which is not desired (nothing places, charges, or
  grants it) and keeps its candidate; a driver recovery's backfill publishes
  directly. Collection deletes a candidate's material only once its recording
  no longer holds its reserved or admitting row, after which that recording
  can never publish or be admitted; a reservation or admitting record older
  than two minutes (a stalled, failed, or crashed launch) is fenced by
  removing it at its version, and its material is then collected. A
  withdrawal removes the material and then the record, or fences a reserved or
  admitting row; an ended generation
  (sandbox gone, replaced, stopped, or deleting) is withdrawn by the sweep; and
  the compute driver's recovery backfills instances it runs without a record and
  withdraws records published before its listing that it no longer lists.
- **Placement and ownership.** A launch admits its instance on the live member
  the consistent-hash ring prefers (`gateway_ring`): one transaction creates
  the owner record, charges the member's capacity, and publishes the
  `Admitting` record, conditioned on that record's version, so an owner always
  has its published instance and a removed record never gains one. A member at
  its 256-instance capacity is skipped. With no live member, or none with
  room, the launch is refused with that reason: it removes the admitting
  record it created, only at the version it created (a concurrent launch of the same
  generation that admitted it first wins), and then that record's candidate
  and material; a removal that fails is left to fencing. One
  `supervisor_instance_owner` record per instance names the member, its
  process, and the ownership term (the sandbox's credential epoch). Records
  change only by compare-and-swap, and a live owner keeps its instances.
- **Capacity.** One `supervisor_pool_capacity` record per member lists the
  routes whose owner record, in any phase, names the member. Every owner
  create, move, or removal is one `Store::write_atomically` transaction with
  the capacity records it changes, conditioned on all of their versions, and a
  full member is refused before anything is written. Two replicas admitting
  the last slot of a member, by launch or takeover, therefore admit one, and a
  stalled admission whose slot was taken meanwhile fails. A takeover prefers
  the route's previous member, whose record already lists it, so a member
  whose process restarted re-adopts its instances even when every member is
  full.
- **Takeover.** Only an instance whose owner failed or left moves. A replica
  records the intent (new owner, next term, the process the runtime will pin,
  a new token lineage), advances the sandbox's persisted epoch with
  `advance_identity_for_takeover`, which revokes the previous owner's
  credentials on every replica, and then grants it. Any replica completes an
  interrupted intent; a stopping, stopped, or deleted sandbox, a replaced
  generation, or a term another lineage holds cancels it. A replica that just
  started waits 30 seconds before taking over, so members reconnect after a
  gateway restart first. The takeover log names its `cause`: `expired`,
  `leaving`, or `restarted`.
- **Credentials.** Each replica mints a takeover term's grant and session
  credentials only for members it serves, from the granted record and the
  persisted identity, and mints them again after half the grant's lifetime.
  Other replicas send the term without credentials; a host that already runs
  it keeps it.

- **Observations.** The replica serving an owner records what the owner reports
  of its instances (`supervisor_instance_report`; no error text), one record per
  instance and ownership term, and every replica judges an instance whose owner
  streams elsewhere from the record of the current owner term, so launch
  readiness and bootstrap completion do not depend on which replica a member
  reached. A report counts for a term only once the member's stream
  acknowledged the snapshot that installed the term, and only if the pass's
  owner record shows that term, so a status from an earlier term is never
  recorded as a later one. A record is rewritten whenever it differs from the
  report, so one another writer replaced is repaired. Reports are listed before
  owners, and only records of terms older than the listed owner, or of
  instances without one, are removed.

Owner records of withdrawn instances are removed once their generation ended,
or two minutes after the withdrawal, after their owner was told to stop them.
Pool members still authenticate with the one shared supervisor token, so a
member identity is asserted by its hello rather than bound to its Pod.

## Optional in-process sandbox updates

`SharedComputeDriver` retains the generated baseline compute-driver trait, and
`ComputeDriverInstance` retains its existing variants. Existing compiled drivers
and factories need no new trait implementation or registration method.

A supporting factory overrides `ComputeDriverFactory::build_with_configuration_updates`
to return its ordinary instance plus a separately registered updater. The default
calls `build` and returns no updater. External drivers serve
`ComputeDriverConfigurationUpdates` on their existing endpoint. Workload updates
require `openshell.compute.update-sandbox-configuration` for image, command, or
environment changes. Metadata-only replacements use one database CAS and update
the label index without invoking a driver.

New updates require operator activation and compatible gateway membership.
Accepted updates recover from private durable intent at startup and in periodic
reconciliation, including when activation is subsequently disabled. Recovery
pages through a partial database index of pending private update records instead
of scanning sandboxes or completed receipts. Acceptance and completion maintain
the indexed status in the same transaction as the intent and lifecycle interlock.
Each gateway keeps automatic recovery backoff in memory. Failed attempts wait
1, 2, 4, 8, then 15 minutes; each failure log includes the attempt and retry delay.
Replicas retry independently, and a gateway restart resets its backoff. A new
operation starts without delay. Completed or deleted updates are removed from
the backoff map as recovery observes them.
An authorized `UpdateSandbox` with no selected fields and the current resource
version resumes immediately, bypassing backoff without reconstructing its selections. Completion retains the
exact operation receipt for idempotent completion across replicas; a newer update
invalidates it. Ambiguous results retain the baseline provisioning interlock.
Explicit deletion can supersede a pending update: the driver only patches the
original immutable resource and never creates a replacement. The Deleting CAS
prevents delayed completion. Cleanup bypasses the pending-driver guard only when
the pending operation ID matches the persisted update intent. Final removal
deletes the sandbox and private intent atomically, retaining that evidence if
cleanup fails or loses a resource-version race.

Metadata replacement preserves gateway-owned keys, including retention, while
other user keys under OpenShell domains remain editable. Completion preserves
later annotation merges accepted through `UpdateConfig`.

A provisioning timeout can be repaired by Stop after its original driver work
settles and cleanup completes. Stop exposes Stopped without discarding the timeout
diagnosis or storage. This lifecycle behavior also applies when updates are disabled.

## Internal secret boundary

Provider credentials and refresh material use `CredentialRuntime`. Sandbox SSH
host keys and shared-supervisor launch material use `InternalSecretStore`, a
narrow interface with explicit object ownership and store, resolve, and delete
operations. Internal consumers do not construct provider records or call provider
delivery APIs. New writes always stage a fresh candidate before the owning
controller publishes its handle with CAS.

Both interfaces use the selected
[`openshell-credential-issuer`](../openshell-credential-issuer/README.md) in embedded
and remote modes. Typed provider, sandbox, and supervisor-instance owners keep
internal secrets separate from provider records. Remote startup initializes no
local value drivers or credential KEK. Embedded startup adopts legacy physical
handles without copying their values, moves inline values into issuer storage,
and atomically publishes value-free ownership journals with the rewritten owner
records. Refresh imports remain dormant until that gateway publication commits;
restart recovery verifies the complete provider/journal/output/epoch bundle
before activation. Replacing an unpublished import generation transfers only its
native copies into durable cleanup, never legacy-owned outputs or material.

Value replacements use fresh backing handles and a version CAS. Operator
reconfiguration allocates a new authorization epoch. Revocation tombstones fence
stale references even when backend deletion fails. Retired handles remain
durably owned until cleanup succeeds. Internal allocation intents are fenced in
the same transaction as SSH identity or supervisor assignment publication;
cleanup can cancel an abandoned intent without racing a late publisher.

Both configuration snapshots hash captured credential versions; provider delivery
captures each version and its expiration from the same metadata observation and
rejects a resolution whose version changed after capture. Collision validation
uses that expiration projection, including after refresh deletion. Rotation
within a reference therefore changes the environment revision without changing
provider records or placeholder identities. The refresh worker uses shared issuer
coordination and a stateless minter registry. `RefreshEngine` owns attempt
orchestration behind minter, refresh-state-store, and post-commit sink traits;
the issuer also owns all four stateless built-in protocol implementations.
The issuer owns periodic sweep execution, scheduling and retry policy. Its
non-secret grant checkpoint also owns admission: owner/ID/epoch checks, deletion,
completed-mint coalescing, uncertain-outcome rejection, and live backoff. The
issuer reloads its immutable grant and output ownership under the distributed
lease before preparing an attempt ID; the engine rejects mismatched request IDs
before invoking a minter.
The issuer owns active grant serialization, enumeration, maintenance, scheduling,
and atomic output publication. Both hosting modes invoke the same private
service handlers through the validated watched client; embedded mode opens no
transport listener. Gateway adapters retain legacy DTO projection for startup
adoption and compatibility tests, not production scheduling. New configurations
reserve fixed pending references before initialization and publish a value-free
gateway handoff. Refresh deletion detaches the grant while preserving output
values, versions, and expiration as static credentials. Standalone container,
Helm, release packaging, audit, and optional private metrics are documented in the
[issuer deployment reference](../../docs/extensibility/credential-issuer.mdx).

Intermediate subject-token exchange checks its versioned intermediate-token cache
before resolving stored subject values. Cache hits still require live attachment,
identity, owner/version metadata, and unexpired subject metadata; a backend outage
does not force a value read for an otherwise valid cached token. Cache misses
resolve the subject and recheck its captured version before exchanging it.

### Provider read sources

`credential_source::ProviderCredentialSource` separates snapshot version capture
and value resolution from backend selection. CredentialRuntime implements the
embedded path. RemoteProviderSource accepts only versioned issuer-reference
handles pinned to its registration and immutable provider/workspace/key owner.
It uses reconciled local metadata, preserves pending/expired output behavior,
and rechecks observed versions after resolution. Inline credentials and legacy
or differently registered handles never fall back to local drivers. Internal
secret storage remains an independent local interface.

Gateway configuration inputs capture versions from the state's selected provider
read source, and provider snapshot builders resolve through the same selection.
Both revision hashes therefore include remote rotations without rewriting
provider records. A captured older version cannot be paired with newer values.
Intermediate subject-token exchange also projects expiration and captures/rechecks
versions through this selection. Metadata checks and intermediate-cache hits do
not read issuer values; misses resolve through the selected source and recheck
the captured version before exchanging the subject. Tests keep issuer metadata
healthy while its value backend is unavailable and prove this ordering.
`CredentialReadPurpose` keeps sandbox delivery, refresh exchanges, and operator
export cache entries separate. Subject misses select refresh purpose; a cached
delivery value cannot satisfy either of the other purposes. Privileged export
uses the selected source with OperatorExport purpose. For issuer-backed grants it
validates the complete owner/reference metadata batch and every grant before any
freshness effect, delegates EnsureFresh to the issuer only when needed, and fences
the final response against provider, profile, and grant version changes. Repeated
exports reuse a sufficiently valid grant rather than reminting.
Public provider get/list calls project expiration through the selected source
before redaction, without resolving values or rewriting records.
Refresh-status reads also use the selected source. Remote reads validate complete
published grant ownership, group outputs by the primary key, and project issuer
status without resolving values or minting. Missing ownership and unsupported
read-only metadata sources fail closed rather than consulting embedded grants;
a final provider-binding fence rejects stale status projections. Version-one
legacy deadlines remain conservative; later issuer versions are authoritative.
Expiration-only mutations that would change or clear an established reference's
issuer-owned expiration fail before publication rather than silently succeeding.
Replacing a static value can set a new expiration; version-one legacy references
retain provider-authored expiration edits. Embedded refresh reconfiguration
rejects differing explicit versioned expirations before staging material or
changing the grant; omitting expiration preserves the current reference's
expiration until rotation. Provider update responses project expiration before
publication without rewriting stored metadata or adding a post-commit failure.
The gateway defaults to the embedded source. An explicit
`[openshell.gateway.credential_issuer]` table selects remote provider delivery,
mutation, export, and status adapters over private-CA mTLS. Startup registers
persisted bindings in bounded pages and waits for metadata reconciliation before
serving. Inline/legacy handles and embedded refresh records require explicit
migration; startup never adopts or resolves them. Internal SSH and launch secrets
continue using the local credential runtime. Selected remote sources now opt in explicitly to static
provider create/update/delete routing through the handoff journal; a selected
read-only source cannot fall back to embedded mutation storage. Partial updates
and metadata-only changes preserve untouched issuer bindings, and deletion claims
retirement without waiting for physical cleanup. Legacy inline/driver records
cannot be implicitly adopted on update. Internal secret storage remains local.
Builtin refresh configuration uses shared profile, material, and attached-sandbox
collision validation, then reserves and initializes an issuer grant before
atomically replacing the entire output epoch. Configuration and material never
enter local refresh state or handoff records. The issuer's pinned descriptor
classifies both encrypted input groups. New references are pending until issuer
scheduling or explicit freshness publishes values; old values/expiry metadata do
not seed the new epoch. Reconfiguration retires complete old bundles, and a
request-ID replay cannot select the replacement epoch. Registered single-output
custom minters use the same publication path. The exact authenticated descriptor
selects the sole output and separates required configuration and secret material;
unknown fields, contrary secret annotations, conflicting enum selectors, profile
refresh overrides, and ambiguous multi-output bindings fail before allocation.
Custom profile declarations remain unsupported remotely. Refresh deletion claims
its published journal before calling issuer `DetachGrant`, then atomically removes
grant annotations from provider handles and converts the journal to static
ownership. Values, reference versions, and issuer expiration remain unchanged.
Retirement and replay reject the claim while it is in progress; reconciliation
resumes interrupted transfers and publishes delivery invalidation. Pending outputs
without first values fail before claiming ownership.
Delivery projects immutable source/grant epochs from issuer references, so
rotation changes snapshot revisions without changing workload placeholder
identity. Reconfiguration selects a new grant epoch and revokes that identity.
Rotation uses the selected issuer:
it validates complete published ownership and authoritative metadata-only owner
checks before minting, then fences the original bundle again before returning.
Workspace mutation exclusion prevents concurrent gateway rebinding. Neither
provider records nor local refresh state are rewritten. Request-ID replay retains
only an explicit scalar status allowlist and a published grant proof, revalidates
all siblings and the epoch locally, and never calls the issuer or mints again.
Retired, missing, rebound, or deleted ownership makes replay unavailable.
`credential_source::delivery_watch` bridges issuer value/grant changes, Unknown,
consumer lag, and reconciliation recovery to local push-session invalidation.
Each replica observes its own watches, so the bridge does not echo peer fanout.
Unchanged health updates do not trigger rebuild loops. Dropping its guard stops
forwarding without canceling issuer-admitted work. Remote startup retains this
guard and the handoff reconciler until shutdown and disables embedded provider
reference migration/notifications and the embedded refresh worker.

Polling configuration reads and push bootstraps defer selected-source metadata
availability errors until provider-environment construction. They deliver valid
authored policy/settings with a domain-separated failed environment revision,
allowing polling supervisors to revoke on a failed fetch and reconnecting push
supervisors to receive an unresolved bootstrap. Failed inputs never resolve
values or seed the environment cache. Equal-version recovery resolves again;
embedded database failures and invalid reference ownership remain ordinary read
errors. Existing live push sessions retain their session-local invalidation path.

### Credential handoff ownership journal

`credential_source::handoff::StaticHandoff` provides the gateway-local,
value-free ownership primitive for remote static credentials and grant bundles. It writes
`credential_issuer_handoff_v1` before contacting the issuer, reserves every
reference before sending any value, and journals a one-shot Filling phase before
value transmission. Interrupted or failed fills recover only through revocation;
they cannot mix values from a new request into an old partial attempt. No provider
value or secret-dependent whole-request fingerprint enters this journal.

A ready static handoff verifies the complete version-two metadata batch and joins its
Published marker with the exact provider create/update in one gateway transaction.
The provider payload must contain only the expected issuer bindings and no inline
values. Cleanup first claims the journal revision, then replays value-free
reservations to discover lost allocation responses and revokes every known
identity. It retains ownership through uncertain cleanup responses. A late owner
cannot publish after that claim, even before remote revocation finishes.

Static RPC adapters use this infrastructure when a remote source is explicitly
selected. Builtin and single-output custom grant configuration use
`prepare_grant`; refresh deletion transfers complete published bundles to static
ownership. The
`spawn_reconciler` worker scans bounded keyset pages, immediately retries committed
Aborting claims, and claims idle unpublished work using a configurable one-minute
to one-hour cutoff. Failed rows retain ownership without blocking unrelated rows;
foreign registrations and live Published bindings are never reclaimed. Filtered pages
advance the raw scan cursor even when no source/provider rows match.
`published_for_provider` discovers live immutable ownership before a mutation.
Remote gateway startup starts this worker with `cleanup_idle_seconds` (default
300, range 60–3600). Published journals refuse direct abort. `publish_replacing` joins
old-journal retirement claims to the replacement transaction, and `delete_provider`
joins them to provider deletion. Both require complete immutable ownership of the
current bindings. Cleanup reloads those committed claims before issuer
revocation; it never infers permission from a missing provider or a display name.
Stale ownership rolls back the whole mutation. Partial replacements preserve
untouched bindings without resolving their values. Old journals mark only replaced
or removed keys for retirement; `cleanup_retired` forgets each retired key only
after confirmed issuer revocation, retaining active siblings and their original
operation IDs. Recovery processes these explicit flags, not parent absence.
`update_preserving` supports metadata-only changes and key removal without issuer
value reads. It rejects reference injection and expiration changes to retained
issuer-owned credentials. Retained static legacy version-one references still
accept provider-authored expiration edits and clears, with a value-free issuer
version check repeated before publication. Version-one projection preserves the
minimum of provider and issuer deadlines; later issuer versions supersede these
legacy fields. Explicit retained-expiration requests authenticate fresh issuer
metadata even for spec no-ops, and carry those exact versions to publication.
Ordinary provider updates cannot replace or remove any configured
grant output, including a complete bundle; use the explicit refresh operations.
Publication derives the label
index from the validated provider payload; payload, labels, and journal commit
or roll back together, including clearing removed labels. The issuer's independent
backing-allocation-to-candidate-journal crash window is not closed by this gateway
journal. Real mTLS tests cover round trips, ambiguous allocation recovery,
one-shot fill failure, cleanup/publication fences, rollback, immutable ownership,
rejection of inline values, and atomic label-index replacement/removal.

`begin_grant` journals a value-free `GrantPlan` (strategy, semantic output/key
mapping, primary key, and scheduling bounds). `reserve` allocates and records the
grant and every output identity together before `fill_grant` transmits any
configuration or refresh material. A lost reservation response is recoverable
from that recipe alone. Grant preparation is one-shot: it journals Filling and
initializes the issuer grant. `fill_grant` then requests its first fresh output
bundle. `prepare_grant` instead permits atomic publication of the pending
version-one bundle without requesting an upstream mint; delivery stays unavailable
until issuer scheduling or an explicit freshness request publishes first values.
A persisted, default-false marker distinguishes pending publication from the
first-value-required path, so older journals do not gain that authority. Failure or
interruption requires abandonment, not a retry with replacement inputs. No
configuration, material, or secret-dependent fingerprint enters gateway storage.

Grant bindings include the issuer grant ID. Publication allows later value
versions when the issuer refreshed before gateway publication, without changing
those bindings. Replacement/deletion claims retire every output of a grant as
one bundle; partial retirement fails before the provider transaction commits.
Metadata-only updates preserve the bundle without reading values. Recovery
replays the grant reservation, deletes the known grant, and forgets the journal
only after confirmed issuer revocation. A cleanup revision claim fences late
initialization/mint completion from gateway publication. Public builtin refresh
configuration uses pending preparation, while callers needing initial fresh
outputs can use the library's first-value-required fill path.

## Operator credential export

`GetProviderCredentials` exports selected profile-declared runtime environment
keys from one provider in an explicitly named workspace. It requires the distinct
`Principal::Operator`, established only from a verified TLS leaf certificate with
`OU=operator` when `mtls_auth.operator_enabled` is enabled. The TLS listener supplies
its certificate fingerprint separately from user identity; the ordinary
identity-only serving path cannot establish an operator.

Operators explicitly inherit user/platform-admin permissions, but not sandbox or
peer identities. Descriptor authorization and a handler guard both protect the
export RPC. Operator mutation admission uses a separate caller namespace from
ordinary mTLS users with the same certificate subject. Credential responses never
enter durable mutation replay or generic interceptor routing.

The export resolver validates the entire selection before minting, resolves only
selected credential handles, and fences provider revisions, refresh epochs, and
profile declarations before delivery. Driver expiration and provider expiration
combine using the earlier timestamp. OAuth minting inputs, broker-only keys, and
supervisor-bound dynamic grants are not exportable. A failed response can still
have committed refresh effects. Missing refresh-owned stored outputs trigger
refresh-on-read; missing static outputs and other credential-backend errors fail
closed without falling back to inline values.

## Refresh coordination

Explicit rotation, background refresh, and operator refresh-on-read share the
same issuer `RefreshEngine` and `RefreshCoordinator`. The issuer scheduler drives
periodic sweeps and owns retry deadlines and candidate-selection policy; gateway
sweep adapters enumerate durable grants, perform maintenance, and publish changes:

- A process-local weak keyed mutex coalesces waiters without retaining deleted
  providers indefinitely.
- A bounded admission queue and executor pool limit detached refresh work.
- PostgreSQL deployments also take a dedicated per-provider/per-credential
  advisory lock; SQLite uses the local mutex. Worker secret cleanup takes the
  same locks and reloads state before changing its resource version.
- A durable `refresh_in_progress` marker and attempt UUID precede upstream minting. A
  `refresh_committing` marker protects the interval between grant persistence
  and provider-handle persistence. Only a completed provider commit publishes
  `refreshed` state, with that attempt UUID as the completed-mint identity in metadata
  annotations. Waiters coalesce against that identity, not bookkeeping changes
  to the resource version.
- Automatic callers recheck live recovery and retry deadlines under both locks.
  A failed mint blocks queued automatic exchanges without disabling scheduled
  worker retries or a separately requested manual rotation.
- Detached refresh tasks complete despite request cancellation, preserving
  replacement refresh tokens returned by the issuer.
- Established output sets capture reference versions before minting. Publication
  atomically commits all versions and the grant receipt, including AWS's three
  outputs. Provider references and their resource version remain unchanged;
  get/list responses project current expiration from reference metadata.
- All four built-in strategies live in the issuer crate behind the shared
  `TokenMinter` contract and registry. No protocol consumes gateway storage DTOs.
  Adapters separate configuration from secret material and translate semantic
  outputs into pinned profile environment keys. The registry preserves failure
  recovery classifications and parks malformed responses. Custom Rust minters
  use `custom:<name>`. Public profiles and configure requests accept exact
  built-in `strategy_name` selectors; a specified enum must agree. Status exposes
  canonical names for legacy grants and registered names for custom grants.
  Remote configure accepts registered single-output custom minters; custom
  profile declarations and multi-output custom configure remain unsupported.
- Existing generation/CAS fencing remains active for deletion and
  reconfiguration. An ambiguous rotating-token exchange is parked for recovery
  rather than automatically consuming the grant again.

A crash or lost database-lock session can leave a parked marker. Reconfigure or
reauthorize the refresh grant after investigating its issuer state. Changing a
marker directly is not a supported recovery workflow.

## Focused verification

```shell
cargo test -p openshell-server --features test-support,prebuilt-z3
cargo clippy -p openshell-server --all-targets --features test-support,prebuilt-z3 -- -D warnings
```

The ignored `postgres_refresh_locks_coordinate_independent_replica_sessions` test
runs under `mise run test:rust:postgres` (see `TESTING.md`) and still accepts
`OPENSHELL_REFRESH_TEST_DATABASE_URL` pointing to a disposable PostgreSQL database.
It exercises independent sessions without the local mutex. Do not point this
fixture at an existing deployment database.
