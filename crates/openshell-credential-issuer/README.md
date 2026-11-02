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
an epoch do not change workload placeholder identity.

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

The four existing built-ins now run behind this contract through gateway-local
compatibility adapters. The gateway records an attempt UUID together with its
pre-mint uncertainty marker and reuses it as the completed-mint receipt after
publication. This does not provide upstream exactly-once delivery: built-in
protocols do not yet send the ID to upstream providers.

This is a partial refresh-engine extraction. Durable grant state, scheduling,
built-in protocol implementations, and provider-record publication still live
in the gateway. Moving those into the issuer, publishing refresh outputs through
stable references, adding the public `strategy_name` field, exposing custom
minters through profiles/configuration, durable reconnectable change streams,
and remote transport remain separate implementation work. The Rust registry
supports custom implementations; it does not yet enable remote minter services.

## Verification

```shell
cargo test -p openshell-credential-issuer
cargo test -p openshell-server --lib --features prebuilt-z3 credentials::references::tests
cargo test -p openshell-server --lib --features prebuilt-z3 grpc::policy::reference_tests
cargo test -p openshell-server --lib --features prebuilt-z3 provider_refresh::
```
