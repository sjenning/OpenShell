# OpenShell extension core

`openshell-extension-core` contains protocol-neutral primitives shared by two or
more OpenShell extension mechanisms. It currently owns extension identity and
audience values, the extension JWT claim contract, refreshable bearer
credentials and the per-service store that holds them, and outbound gRPC
transport construction for HTTP, HTTPS, and Unix sockets.

`ExtensionKind` is non-exhaustive so additional extension points can join the
shared identity and audience model without breaking consumers. A new kind must
still define its own registration, transport, and authorization semantics
before gateway wiring accepts it.

Outbound HTTPS authentication is selected through the shared
`ExtensionServerTrust` policy. Platform roots and operator-provided CA bundles
are implemented today. The non-exhaustive policy boundary allows future
SPIFFE X.509-SVID or public-key pinning support to be added once without
changing middleware and interceptor clients independently. Unix sockets retain
their local operating-system access boundary.

`ExtensionClientIdentity` adds outbound mTLS using inline PEM, certificate/key
files, or SPIFFE X.509-SVIDs from a local Workload API. Identity-bearing channels require HTTPS and never downgrade to plaintext.
File sources are read on every TLS connection, including channel redials; a
partial, malformed, or missing replacement fails closed rather than reusing old
credentials. Existing sessions retain their negotiated identity until reconnect.
Certificate/key paths and contents are redacted in debug output. Server CA and
DNS verification remain mandatory. The mTLS connector constructs TLS through
`openshell-crypto` and negotiates HTTP/2; legacy identity-free tonic TLS remains
dependency-owned.

The SPIFFE source requires an explicit identity and an absolute local Unix socket.
Every dial fetches fresh SVIDs with a bounded timeout and selects exactly one
certificate whose URI SAN matches that identity; it never falls back to the
first/default SVID. Missing, ambiguous, unavailable, or invalid identities fail
closed. The Workload API supplies credentials, not an alternate verifier: server
CA/DNS validation still applies, with trust bundles configured independently.
Socket access permissions remain the local credential-source trust boundary.

Middleware- or interceptor-specific protobuf clients, policy selection,
orchestration, and lifecycle management stay in their owning crates. Gateway
signing authority also stays in `openshell-server`. This ownership rule keeps
this crate from becoming a general-purpose dumping ground as extension support
grows.
