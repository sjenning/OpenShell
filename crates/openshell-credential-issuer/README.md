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

## Refresh coordination and minters

`RefreshCoordinator` owns process-local grant locks, bounded admission, executor
limits, and detached execution. Queue waits can time out; an executing mint
cannot be cancelled by that timer or by the caller disconnecting. Maintenance
uses the same grant lock. The gateway still acquires its distributed lease and
rechecks authorization epochs, completed-mint receipts, and retry eligibility
inside that local exclusion before minting.

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
profile environment keys. It records an attempt UUID together with its
pre-mint uncertainty marker and reuses it as the completed-mint receipt after
publication. This does not provide upstream exactly-once delivery: built-in
protocols do not yet send the ID to upstream providers.

`RefreshEngine` now owns the attempt lifecycle behind `TokenMinter`,
`RefreshStateStore`, and `RefreshSink`. It takes local exclusion and a distributed
lease, prepares a durable attempt, resolves material, invokes the minter, commits
outputs, then notifies the sink. A coalesced attempt does not mint or notify.
Mint failures are recorded before they return; publication failures retain the
store adapter's recovery rather than being overwritten by a generic mint error.

The gateway store adapter retains epoch/revision fencing, retry eligibility
checks, and rotated-token staging. It captures output versions before minting,
then stages fresh backings and atomically publishes the whole output set with
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
and remote transport remain separate implementation work. The Rust registry
supports custom implementations; it does not yet enable remote minter services.

## Verification

```shell
cargo test -p openshell-credential-issuer
cargo test -p openshell-server --lib --features prebuilt-z3 credentials::references::tests
cargo test -p openshell-server --lib --features prebuilt-z3 grpc::policy::reference_tests
cargo test -p openshell-server --lib --features prebuilt-z3 provider_refresh::
cargo test -p openshell-server --lib --features prebuilt-z3 persistence::tests::sqlite_
```
