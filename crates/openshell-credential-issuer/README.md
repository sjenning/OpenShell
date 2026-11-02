# Credential issuer library

This crate owns embedded credential reference state. It does not yet host a
service or run refresh workers. Secret values remain in the existing credential
drivers; issuer state contains only ownership metadata, encoded opaque handles,
versions, expiration, revocation, and pending handle deletions.

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
backend allocation and reference publication. Refresh scheduling, durable mint
attempts, durable reconnectable change streams, minter registration, and remote transport
remain separate implementation slices.

## Verification

```shell
cargo test -p openshell-credential-issuer
cargo test -p openshell-server --lib --features prebuilt-z3 credentials::references::tests
cargo test -p openshell-server --lib --features prebuilt-z3 grpc::policy::reference_tests
```
