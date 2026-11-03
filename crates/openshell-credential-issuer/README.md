# Credential issuer library

This crate owns credential references, refresh coordination and persistence,
stateless minter contracts, authenticated store/refresh/minter library hosts,
and an autonomous refresh/recovery worker. Credential drivers store values;
reference metadata contains ownership, opaque handles, versions, expiration,
revocation, and pending deletions. Known mint results use encrypted native spools.
The experimental standalone binary hosts both private services. Container/Helm
packaging, issuer audit/metrics integration, and gateway remote-source wiring
remain incomplete. See [standalone configuration](../../docs/extensibility/credential-issuer.mdx).

## Reference lifecycle

- `adopt` registers a legacy handle at version 1. Concurrent adoption is
  idempotent and cannot change its workspace, provider ID, or credential key.
- `replace` commits a fresh, immutable backing handle with an expected credential
  version. The reference identity stays stable and the value version advances.
  Versions after adoption own their expiration independently of the provider's
  legacy expiration metadata.
- `revoke` persists a tombstone before backend deletion. Neither startup
  migration nor a retry can turn an old authorization epoch into a live one.
  Operator reconfiguration must allocate a new reference.
- Superseded handles and revoked values stay in `pending_deletions` until the
  backend confirms deletion. Cleanup acknowledgement changes the storage
  revision, not the credential version, and cannot discard concurrent rotations.
- `replace_many` publishes a complete output set atomically. Every reference must
  match its expected value version and immutable owner; candidates cannot alias
  any group member's live or retired backing. A single stale or revoked member
  rejects the whole set. Adapters without native transactions fail closed rather
  than publishing sequentially.

`prepare_replacements` validates a group without side effects and returns
storage-revision-fenced writes. A refresh store can include those writes, its
grant receipt, and provider-owner checks in one native transaction. Gateway
persistence provides non-mutating `AtomicWrite::Check` preconditions: PostgreSQL
locks the checked row until commit; SQLite uses an immediate write transaction.
Neither check advances the owner's version or changes its timestamps.
Established handle-backed refresh grants now use this transaction to publish all
output versions and the completed-mint receipt together. First mint and legacy
inline outputs still establish their references through the provider-record path.
Reconfiguration clears prior mint receipts; the new authorization epoch's first
mint allocates fresh references rather than rotating the old epoch's set.

`ReferenceStateStore` implements durable create-only and compare-and-swap writes.
The gateway adapter stores these records in its object database. PostgreSQL and
SQLite use the same reference contract; credential concurrency does not depend
on a process-local mutex.

## Gateway integration

The gateway preserves existing driver handles as public-record reference
identities and uses a hashed index to find their issuer-owned state. Startup
adopts provider handles without changing provider records or reading secret
values. Refresh material is adopted when resolved. Internal SSH keys and launch
material bypass issuer references and retain their local driver path.

Configuration inputs capture reference versions without resolving values. Both
snapshot revision hashes include those versions. Embedded version and revocation
notifications feed the existing provider fanout, including peer gateways. A local
notification overflow invalidates all connected sessions. The provider snapshot verifies
that resolved versions match its captured inputs; a concurrent rotation returns
`ABORTED` rather than pairing a new value with an old revision. Versions within
an epoch do not change workload placeholder identity. Provider get/list responses
project current expiration metadata without resolving secret values. Intermediate
subject-token cache keys include the subject reference version, and subject
resolution fences that version before an exchange.

The driver adapter stages a new backing handle before its reference CAS. Retired
handle cleanup is retried on later replacement or deletion; pending cleanup
survives restart. This is not yet a general orphan scanner for a crash between
backend allocation and reference publication.

## Storage backend boundary

`backend::CredentialDriver` owns the low-level driver contract and adapters for
encrypted database, Kubernetes Secrets, and Vault storage. The gateway reexports
the trait for compatibility and still composes its local registry, subprocess
lifetimes, and object-store adapter. Sharing the contract does not send SSH host
keys or launch material to an issuer: `InternalSecretStore` remains local and
retains its own backend ownership. The issuer can compose these same first-party
drivers without depending on `openshell-server`.

These are raw legacy driver requests, not an authorization boundary. In
particular, the database driver binds its legacy `provider` and credential-key
fields. An issuer service must derive an immutable per-backing physical owner
from authenticated namespace and immutable owner metadata (or retain the original
physical owner with its backing). Do not pass a mutable display name or rely on extra request
fields that a particular driver does not enforce.

`storage::CredentialStorage` supplies that namespace-bound addressing for new
issuer-owned backings. It projects authenticated namespace, immutable owner,
storage purpose, and a fresh allocation UUID into safe physical names. Including
the allocation in version-two owner addressing protects even drivers that retain
one value per provider/key and ignore the object ID. Version-one backings retain
their original address for resolution and deletion. The wrapper preserves the
backend's opaque handle separately from its configured registration, validates
batch correlation and expiration, and sanitizes backend diagnostics. Different
gateways cannot resolve or delete one another's backing even when their supplied
logical owner fields match. This wrapper is separate from the gateway's legacy
local runtime and does not rewrite existing backend identities.

## Standalone persistence

`repository::Repository` owns a separate, versioned SQLite/PostgreSQL schema.
`for_gateway` accepts an authenticated `GatewayScope`; every row and event is
partitioned by both the derived namespace and durable creating identity.
Workspace and immutable-owner checks remain required above this storage layer.
Payloads are opaque and redacted in Debug output. Persist values only through
the encrypted database driver or the configured external credential backend,
not as plaintext repository payloads.

Native transactions combine revision checks, multi-output writes, completion
receipts, value-free events, and namespace-wide sequence allocation. Failed
checks roll everything back, including sequence advances. Enumeration and event
replay use bounded pages. The initial journal retains all events; a watch adapter
must request reset/full reconciliation when it cannot establish a valid cursor.

PostgreSQL refresh leases use transaction-scoped advisory locks on a separate
pool, release on cancellation/drop, and cannot starve data commits by occupying
the data pool. SQLite relies on shared engine-local exclusion and durable CAS;
use PostgreSQL for multiple issuer replicas. Schema initialization rejects newer
versions and serializes PostgreSQL migrations across startup replicas. The
repository backs both CredentialStore and CredentialRefresh RPC hosts.

`Repository::backend_objects` adapts the encrypted database driver into a
reserved physical-object partition that authenticated gateway scopes cannot
select. It preserves encrypted envelopes, names, labels, and revision fences
without gateway storage or provider DTOs.

`Repository::references` adapts scoped metadata to `ReferenceRegistry`, enforcing
workspace authorization, immutable owners, monotonic value versions, retained
retired backings, and permanent tombstones. Cleanup-only updates advance storage
revisions without emitting value-change events. `prepare_many` exposes fenced
writes and events so the host can atomically commit them with grant receipts and
owner checks. SQLite and PostgreSQL tests cover that combined publication path.

## Durable grant metadata

`Repository::grants(scope)` stores issuer-owned definitions, fixed output
bindings, material handles, schedules, status versions, attempt identity, and
encrypted result spools. Configuration and material remain backend references,
not inline plaintext. The typed adapter rejects definition/epoch changes,
attempt replacement during an unresolved exchange, deletion resurrection,
unmatched completion receipts, and loss of staged/retired material ownership.
Status changes emit durable `grant` events; cleanup-only storage revisions do not.
Workspace-filtered enumeration advances its scanned cursor even on empty pages.

`GrantRepository::prepare` returns a fenced mutation/event for the host's native
transaction, not an independently committed grant publication. The caller must
include fixed output-reference writes, output-binding/owner fences, completed
receipts, and artifact ownership transfers in that same transaction. SQLite and
PostgreSQL tests join pending output allocation and later value/receipt publication,
recover an encrypted known result through an independent pool, and prove failed
fences roll back outputs, grant state, receipts, and events together.

`service::CredentialRefreshService` composes this adapter with the shared engine
and autonomous recovery/sweep. Gateway source selection is explicit; public
builtin and single-output custom grant configuration and rotation use the selected
issuer with value-free gateway journals and metadata-only replay. Custom profile
declarations and multi-output custom configuration remain pending. `DetachGrant`
serializes with minting and deletion under the grant lock and distributed lease.
It atomically stops refresh, releases output-binding guards to static ownership,
and retires configuration/material without changing output references, values,
versions, or expiry. Detached grants can never mint or revoke those static outputs;
static deletion owns subsequent cleanup. Grants without published values cannot
be detached.

## Refresh coordination and minters

`RefreshCoordinator` owns process-local grant locks, bounded admission, executor
limits, and detached execution. Queue waits can time out; an executing mint
cannot be cancelled by that timer or by the caller disconnecting. Maintenance
uses the same grant lock. The gateway acquires its distributed lease inside
that local exclusion and reloads durable state before invoking issuer admission
policy.

`TokenMinter` receives non-secret configuration, resolved secret material, a
strategy name, and a durable attempt ID. It returns semantic output IDs,
expiration, and optional replacement secret material. Requests and responses
redact their values in `Debug`. Minters have no provider records, credential
handles, storage interface, or scheduling authority.

`MinterRegistry` pins descriptors at registration, prevents duplicate names,
reserves `custom:<name>` for extensions, validates required inputs and declared
outputs, and preserves classified failure recovery. Malformed or expired
responses park the attempt rather than publishing values or automatically
repeating an exchange whose outcome may be uncertain.

`builtins::registry()` registers issuer-owned OAuth refresh-token, OAuth client
credentials, Google service-account JWT, and AWS STS minters. Their protocols use
only attempt-local inputs and return semantic outputs directly; they have no
dependency on gateway storage DTOs. JWT signing and first-party TLS initialization
use `openshell-crypto`; AWS SDK signing and transports remain dependency-owned.
Production STS endpoints come from the region, not request material. The explicit
`test-support` registry permits only HTTP loopback STS overrides; enabling that
feature does not change the production registry.

The gateway maps durable grants to requests and semantic outputs to pinned
profile environment keys. It records the issuer-allocated attempt UUID together
with its pre-mint uncertainty marker and reuses it as the completed-mint receipt after
publication. This does not provide upstream exactly-once delivery: built-in
protocols do not yet send the ID to upstream providers.

`RefreshEngine` now owns the attempt lifecycle behind `TokenMinter`,
`RefreshStateStore`, and `RefreshSink`. It takes local exclusion and a distributed
lease, prepares a durable attempt, resolves material, invokes the minter, commits
outputs, then notifies the sink. A coalesced attempt does not mint or notify.
Mint failures are recorded before they return; publication failures retain the
store adapter's recovery rather than being overwritten by a generic mint error.
The engine allocates a fresh attempt ID under the lease and requires the resolved
request to carry that exact ID before invoking a minter. Missing or mismatched
IDs park the attempt for investigation. UUIDs are correlation/idempotency keys,
not authorization tokens or cryptographic secrets.

`grant::GrantCheckpoint` owns admission policy over the freshly reloaded grant:
immutable owner/ID/authorization-epoch checks, deletion rejection, completed-mint
coalescing, unresolved-exchange parking, and live automatic retry eligibility.
Explicit rotation bypasses backoff, never an uncertain mint. The checkpoint
contains no material, handles, profiles, or upstream error bodies. It is a policy
projection, not a new durable serialization format or substitute for a lease.

The gateway store adapter retains serialization, owner liveness checks,
epoch/revision-fenced writes, and rotated-token staging. It captures output
versions before minting, then stages fresh backings and atomically publishes the whole output set with
its completed-mint receipt and a provider-version precondition. A changed owner,
grant, or output rejects the set without publishing siblings. Lost commit
acknowledgements require the exact completed attempt receipt to establish success;
otherwise possibly committed candidates remain intact. The sink
invalidates provider delivery through the existing embedded fanout. This callback
is not a durable change stream and can duplicate callers' existing invalidations.

`scheduler` owns due-work selection, retry deadlines, lead-time rounding, and
live automatic retry eligibility. Its periodic sweep driver starts immediately,
serializes sweeps, delays missed ticks instead of bursting, and survives sweep
errors. A non-secret `GrantSchedule` is only a scheduling projection: the store
adapter must reload and recheck it under the distributed lease. Tombstones and
pending cleanup remain eligible for maintenance even when a mint is parked.

Durable grant serialization, grant enumeration/maintenance, and provider-record
publication still live in gateway adapters. Public profile and configure
`strategy_name` fields now support named built-ins with enum/name conflict checks;
status projects canonical names for legacy grants. New grants persist known names
using the existing durable enum; existing grants need no migration. Unregistered custom names
fail closed. Moving durable adapters into the issuer, exposing registered custom
minters through configuration, durable reconnectable change streams,
and issuer-service transport remain separate implementation work. The private
store, refresh, and minter RPC contracts live under `proto/`; they are not served
by the gateway listener.

## Encrypted mint-result spools

`mint_spool::MintResultSpool` seals a known-success result, including rotated
material, using the existing encrypted-database credential crypto adapter. The
adapter uses `openshell-crypto`; this adds no independent cryptographic backend.
Authenticated envelope identity binds gateway namespace, immutable owner, grant
ID, authorization epoch, and attempt. Replicas must share the explicitly
configured encryption key. Ciphertexts and crypto errors expose no result values.

A durable grant adapter must persist these bytes with its revision/epoch/attempt
fences before external material/output staging. Recovery can then finish the
known result instead of repeating an upstream exchange. Even expired results
remain decryptable: recovery must preserve rotated material before deciding
whether fresh outputs need another mint. The helper bounds source/envelope sizes
and does not perform persistence, publication, or recovery itself. The refresh
host persists the ciphertext with native grant fences before external staging.

## Remote minter adapter

`remote_minter::RemoteMinter` connects using private-CA mTLS through
`openshell-extension-core`, discovers exactly the configured `custom:<name>`,
and validates/pins its descriptor using the embedded registry's rules. Register
the adapter in `MinterRegistry` so requests and returned output/material sets
receive the same validation as built-ins. Discovery has a ten-second deadline;
mints have a two-minute deadline and are never automatically replayed.

Only explicit, valid status/action/retry combinations permit retries. Missing,
malformed, or unknown failure details park the attempt for investigation; network
errors and deadlines may follow an upstream side effect. Arbitrary remote status
messages, failure codes, and subtypes are discarded in favor of static local
diagnostics. Configured minter services remain responsible for authenticating
and authorizing issuer identities. The gateway configures registered single-output
custom strategies through its selected issuer. Custom profile declarations and
multi-output configuration remain future work.

## CredentialStore RPC host

`service::CredentialStoreService` serves the private store contract through
`into_service()` over a mandatory-client-auth listener. Start
`spawn_maintenance()` to retry owned cleanup. Every RPC authenticates its TLS
peer; value access additionally checks workspace, durable creator, and immutable
owner. All batch members pass authorization before any backend value read.
Resolution captures versions, resolves immutable backings, then rechecks the
whole snapshot. No partial result escapes a failed sibling or version fence.

Put/delete use bounded, detached coordination plus PostgreSQL leases, durable
idempotency receipts, and atomic reference/event publication. Reusing a key with
different intent fails. Intent fingerprints that include secret input stay
encrypted in the credential backend, not as unkeyed plaintext hashes in the
metadata database. Audit-only display names do not select storage or identity.

Known staged candidates are journaled. Publication consumes their revision-one
journal rows in its native transaction; cleanup first claims a row by advancing
its revision, fencing even a late publisher that lost its lease. Retired values
remain reference-owned until confirmed deletion. Cleanup currently enumerates
configured gateway/workspace scopes. Disabled scopes remain retained for later
reconciliation, and a general backend orphan scanner for the allocation-to-journal
crash window is still missing. The host does not claim crash-proof allocation
recovery for drivers without preallocation/discovery.

`ReferenceRegistry::reserve` and `ReferenceState::reserved` allocate pending
output identities at version one without fake backend values. Metadata
inspection exposes the pending flag; ordinary resolution fails until the first
mint atomically publishes version two. First publication and revocation of an
unminted reservation never queue empty/fake handles for deletion. Existing
metadata defaults to materialized values, preserving legacy version-one adoption.

Metadata inspection returns versions, availability, and expiration without backend
reads or values. Value responses bound cache TTL by effective expiration and configured
TTL. Watches replay durable namespace-wide sequences, begin/reset with full
reconciliation, and use value-free checkpoint/heartbeat frames after replay or
filtered events. A checkpoint alone does not complete client reconciliation.
Unknown cursors reset; stream errors require clients to invalidate caches and
fail closed. The journal currently retains all events.

The standalone daemon composes this host with CredentialRefreshService and
shared storage/coordination. The gateway has selected-source delivery, static
mutation journaling, and operator-export adapters. Gateway TOML source selection
also starts delivery invalidation and cleanup reconciliation. Public grant
configuration for builtin and single-output custom strategies and rotation use
that source. Refresh deletion preserves published outputs as static credentials;
custom profile declarations and multi-output custom configuration remain pending.

### Value-free static reservations

`ReserveSecret` allocates an immutable, pending version-one reference and a
value-free idempotency receipt in one native transaction. It never allocates a
backend value or secret-dependent fingerprint. Replays return the original
binding even after fill or revocation; display-name changes are ignored, while
another owner or operation cannot reuse the key. Capabilities advertise support
additively, so read-only clients can still connect to earlier issuers.

A gateway can persist a value-free reservation intent, replay that intent after
an uncertain allocation response, then journal the known reference before
sending a conditional `PutSecret(expected_version = 1)`. First fill publishes
version two. Revoking the known pending identity fences a late fill through the
same native reference CAS and permanent tombstone. The gateway need not persist
the provider value to discover or clean up an ambiguous fill. This is the
issuer-side primitive used by the gateway's static handoff journal and configured
remote source. The existing backing-allocation-to-candidate-journal crash window
remains.

## CredentialRefresh RPC host

`service::CredentialRefreshService` hosts all nine refresh RPCs alongside a
CredentialStoreService. Supply a pinned minter registry and MintResultSpool
using a shared encryption key across replicas. The host never reads gateway
profiles. Creation encrypts configuration/material, allocates fixed pending
outputs, binds them to the grant's immutable epoch, and commits ownership,
idempotency receipts, and value-free events together. Default lifetime is one
hour, default lead time is five minutes, and requested lifetime is bounded to
twelve hours. The issuer serving window never exceeds that lifetime; this does
not shorten the upstream credential's actual validity.

`ReserveGrant` allocates an immutable grant epoch and its fixed pending output
references without configuration, refresh material, backend allocations, or
secret-dependent fingerprints. Its value-free receipt replays the original
identities after initialization or deletion. `ListStrategies` advertises this
additive capability; earlier read-only clients remain supported. Reserved grants
cannot mint through scheduling, EnsureFresh, or RotateGrant.

After journaling those identities, a gateway can send `InitializeGrant` with
configuration and refresh material. The host encrypts the inputs and atomically
commits initialization, candidate ownership, the completed replay receipt, and
the pending status transition. Only then can scheduling or an explicit refresh
mint. Configuration can be initialized once; another operation cannot replace
it, change the epoch, or rebind outputs. Exact completed initialization replays
even after minting/deletion, without reinitializing or minting. Deleting a reserved
grant revokes its pending outputs and permanently fences late initialization.
Gateway builtin refresh configuration uses these primitives and publishes
pending references without requesting an upstream mint. It never persists the
configuration or material in gateway refresh records.

Store and grant mutations share the gateway's durable idempotency namespace.
Rotation claims its intent with the pre-mint uncertainty marker, before any
upstream call. Completed results or classified failures replay without minting;
reusing the key for another operation/intent fails. Pending intents survive
cancellation. Legacy static-store receipts still decode as completed.

The host persists an encrypted known-success result before external staging,
stages rotated material before outputs, then atomically publishes every output,
the exact mint-completion receipt, material ownership, grant status, rotation
result, and events. Ambiguous acknowledgments recover through the per-attempt
receipt, not just the latest grant receipt. Backend outages after the spool
commits leave recoverable publication work and never repeat the upstream call.
Before that native spool commit, detached work retains the known result while
retrying a transient database failure. A process crash with no durable result
still parks the unresolved attempt; it does not promise exactly-once upstream
execution.

`spawn_worker()` performs serialized scheduling, known-result recovery, orphaned
attempt parking, and owned cleanup, including store reference/candidate cleanup.
Retired-material backend deletion failures retain cleanup ownership for a later
sweep without suppressing live scheduled refresh or known-result recovery.
Coordination, ownership, and persistence failures still fail closed.
Parked unknown outcomes reject scheduled and manual minting. A late known result
for the same immutable attempt can recover without minting again, but cannot
cross deletion or an epoch change. Grant deletion revokes all outputs atomically
before physical cleanup and retains tombstones. Watches use the same durable
reset/checkpoint model as store watches and never return credential values.

SQLite supports one runtime; use PostgreSQL for replicas. mTLS tests exercise the
actual generated clients for both services. PostgreSQL tests use independent
service pools to coalesce mints, replay intents, recover known results and
complete cleanup. The standalone daemon supplies validated TOML composition,
mandatory mTLS, storage, and registered minters. Gateway remote mode requires
explicit gateway configuration; container/Helm issuer packaging remains pending.

### Graceful host shutdown

Stop scheduler/maintenance handles, call `CredentialStoreService::stop_admission()`,
and stop accepting transport connections before awaiting `drain()`. The shared
coordinator rejects new mutations but retains already queued and detached work.
Store and grant watches close even when their receivers are backpressured, so
long-lived streams cannot hold a graceful transport shutdown open indefinitely.
Await both the transport and the drain before exiting. A canceled drain wait
does not cancel an admitted mint; another clone can resume waiting.

The host owns the shutdown deadline. An elapsed deadline or process termination
is not evidence that an upstream exchange failed and never authorizes replay.
Normal uncertainty preparation and known-result recovery remain authoritative.
The standalone daemon uses these lifecycle methods on SIGTERM and Ctrl-C.

## Remote issuer client

`remote_issuer::RemoteIssuer` is a private-CA HTTPS/mTLS client for all store and
refresh operations. Connection discovery requires protocol one, bounded batch
and response sizes, watch support, expiration, and metadata inspection. Calls
have bounded admission, message sizes, and deadlines. Mutations are never
replayed automatically; a caller recovering an ambiguous result must retain and
reuse its original idempotency intent.

The client rejects partial/duplicate resolution batches, mismatched versions,
secret-bearing metadata, changed fixed output sets, malformed catalogs/status,
and invalid watch frames. It subtracts elapsed request time from cache budgets
and clamps them to expiration. Errors contain static diagnostics without remote
messages or details. Watch connections resume from durable namespace cursors;
reset/checkpoint frames do not reconcile caller state. Broken, malformed, or
stalled streams terminate and require a new watch. This is the transport adapter;
WatchedIssuer supplies the cache/reconciliation layer used by explicit gateway
remote-source selection and provider/config-delivery integration.

## Watched remote values

`remote_issuer::WatchedIssuer` wraps one authenticated RemoteIssuer with secret
and grant watch controllers, value-free notifications, local metadata getters,
and a bounded value cache. Register persisted reference/owner and grant bindings
before waiting for synchronization. `wait_synchronized` also requires reconciled
tracked metadata; a checkpoint by itself is insufficient. Inspection never reads
backend values.
A failed batch is inspected individually so one missing binding cannot revoke
unrelated siblings.

Both watches must be healthy before any cached value is usable. Breaks, resets,
and stalled/malformed streams discard cached values, invalidate affected local
metadata, and reconnect with the last validated namespace cursor. Reconciliation
never replays an upstream mint. Fresh authenticated reads can still succeed while
a watch is unknown, but return zero cache TTL. Candidates captured before a reset
or disconnect cannot repopulate the cache after synchronization resumes.

Cache hits require the complete batch, exact immutable owners, purpose, and
explicit pinned versions. A miss sends the whole batch to the issuer, not just
missing members. After reading, watch observations fence the entire result before
cache publication. Budgets subtract RPC/processing time and expire at the earlier
monotonic TTL or wall-clock credential expiration. Limits are 512 cached values,
eight MiB of value bytes, 4,096 tracked references, and 1,024 tracked grants.
Terminal tracked entries are reclaimed under capacity pressure, including
logically deleted grants awaiting physical cleanup; live bindings are never
evicted. Authenticated status reads can still report `deleting` without restoring
active tracking. Allocating mutations reserve tracking capacity for their
complete output bundle before contacting the issuer, so a historical tombstone
does not impose a process-lifetime quota or turn a committed allocation into a
local capacity error. Per-registration observation tokens prevent old in-flight
reads from restoring metadata after a terminal entry was reclaimed and
registered again. Revocation remains durable at the issuer. Independent secret
and grant metadata epochs prevent cross-stream starvation; a distinct recovery
notification follows complete reconciliation without treating idle checkpoints
as value changes.
Metadata retains no value buffers or audit display names. Idle expired values
are pruned on checkpoints.

`known_secret` and `known_grant` perform no network I/O and fail closed while
metadata is unknown. Gateway request paths can use these to avoid issuer calls
on intermediate-token cache hits. Notifications contain no values; consumers
must invalidate/reconcile on Unknown or broadcast receiver lag. Dropping the last
wrapper aborts its watch workers and releases cached state, not already admitted
issuer work. Real mTLS tests close live sockets, rotate while disconnected, and
verify cursor recovery, metadata-only reconciliation, TTL expiry, and version
invalidation. Gateway remote startup registers persisted bindings, waits for
reconciliation, and bridges changes and health transitions to local push delivery.

## Hosted minters

`hosted_minter::HostedMinter` hosts one registered `custom:<name>` through the
private TokenMinter service. Use `into_service()` with a mandatory-client-auth
listener such as `ExtensionTlsAcceptor`. `auth::IssuerPolicy` supplies a separate
exact allowlist of issuer certificate identities; gateway workspace permissions
and request identity headers do not grant minter access.

The adapter pins the descriptor once, rejects undeclared inputs before invoking
the implementation, bounds messages to 1 MiB and concurrent exchanges to 1–64,
and returns explicitly classified overload before admitting an exchange.
Admitted work survives caller disconnect. A 110-second response deadline leaves
time for the remote client's two-minute deadline; timeout, panic, invalid output,
and invalid failure classifications report investigation/parked. A timed-out
exchange retains its executor slot until completion. The host does not persist
results, replay requests, or promise exactly-once execution. Implementations may
use the supplied durable attempt ID for upstream-supported idempotency.

Only validated action/schedule/status combinations cross the protocol. Arbitrary
plugin/upstream messages, status details, failure codes, and error subtypes are
replaced with static local classifications. Minters receive only attempt-local
config and material, not provider records, reference handles, or storage APIs.
The adapter is a library host, not yet a standalone deployment command.

## Remote caller authorization

`auth::GatewayPolicy` maps exact certificate SPIFFE URI identities to explicit
workspace sets. This applies to both file-based certificates with URI SANs and
Workload API SVIDs. It derives caller identity only from verified TLS connection
extensions, never headers, bearer claims, or supplied owner metadata. The
facade-owned `ExtensionTlsAcceptor` supplies verified peer metadata; tonic TLS
connection info is also supported for existing authenticated listeners.

`GatewayScope` supplies a stable identity-derived storage namespace across key
and certificate rotations. Authorization checks both the durable creating
identity and immutable workspace/provider-ID/credential-key owner. A matching
supplied owner never permits access to another gateway's object. Missing TLS,
unknown or ambiguous identities, unconfigured workspaces, and wildcard workspace
bindings fail closed. Services must authenticate every operation, select storage
by that namespace, and check the bound owner before reading values or mutating
state. CredentialStoreService and CredentialRefreshService apply these checks
to every hosted operation. Neither host enables gateway remote mode by itself.

## Verification

```shell
cargo test -p openshell-credential-issuer
# Against a disposable PostgreSQL database (creates issuer-owned tables):
OPENSHELL_TEST_ISSUER_POSTGRES_URL=postgres://localhost/issuer_test \
  cargo test -p openshell-credential-issuer postgres -- --ignored
cargo test -p openshell-server --lib --features prebuilt-z3 credentials::references::tests
cargo test -p openshell-server --lib --features prebuilt-z3 grpc::policy::reference_tests
cargo test -p openshell-server --lib --features prebuilt-z3 provider_refresh::
cargo test -p openshell-server --lib --features prebuilt-z3 persistence::tests::sqlite_
```
