# Credential issuer library

This crate owns embedded credential reference state, local refresh coordination,
and a stateless token-minter contract. It does not yet host a service or run
refresh workers. Secret values remain in the existing credential drivers;
persisted reference state contains only ownership metadata, encoded opaque
handles, versions, expiration, revocation, and pending handle deletions.

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
and authorizing issuer identities. Gateway custom-profile/configuration wiring
and a hosted minter server adapter remain future work.

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
state. The policy primitives do not yet host store/refresh RPCs.

## Verification

```shell
cargo test -p openshell-credential-issuer
cargo test -p openshell-server --lib --features prebuilt-z3 credentials::references::tests
cargo test -p openshell-server --lib --features prebuilt-z3 grpc::policy::reference_tests
cargo test -p openshell-server --lib --features prebuilt-z3 provider_refresh::
cargo test -p openshell-server --lib --features prebuilt-z3 persistence::tests::sqlite_
```
