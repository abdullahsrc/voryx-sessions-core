# voryx-sessions-core

Selected implementation from Voryx Sessions, published so the security-sensitive parts of the project can be inspected without publishing the full application.

The repository focuses on signed request handling, session-scoped authorization, mailbox capabilities, replay state, selected native cryptographic operations, and deletion lifecycle code. It keeps the original module boundaries where practical.

This is not a standalone Sessions server. The UI, server bootstrap, deployment configuration, transport stack, and most persistence code are intentionally outside this repository.

## What is here

```text
server/
  signature-verification.ts
  crypto-canonical.ts
  crypto-primitives.ts
  request-nonce-store.ts
  postgres-schema-lock.ts
  mailbox-plane-store.ts
  native/crypto-native.ts
  route-modules/
    request-auth.ts
    session-access-guards.ts
    mailbox-message.ts
    mailbox-plane-state.ts
  storage/
    session-access-policy.ts
    storage-deletion-purge.ts
    message-lifecycle-store.ts
    session-core-store.ts
    key-lifecycle-store.ts
    storage-interfaces.ts

shared/
  schema.ts
  sender-scope.ts

native/
  voryx-crypto/
  voryx-crypto-wasm/

docs/
  PROTOCOL_SPEC.md
  SECURITY_PROPERTIES.md
  THREAT_MODEL.md
```

A few supporting modules are included because the selected paths depend on them directly.

## Request and authorization boundaries

Guarded requests bind a signature to the request method, normalized path, body hash, timestamp, nonce, key ID, and public key.

Nonce consumption can use in-memory state or PostgreSQL. The PostgreSQL path records scoped and key-global nonce state transactionally so a valid signature alone is not enough to replay a request.

Session membership and message access are deliberately separate checks. A key can belong to a session without having the grant state required to read message state.

Mailbox capabilities are scoped to the session, plane, key identity, and lifetime, and are checked against current authorization state when used.

## Native cryptography

Selected operations cross a Rust boundary rather than being reimplemented in the TypeScript layer. The published native source includes Ed25519, HKDF-SHA-256, AES-256-GCM, SHA-256, constant-time comparison, canonicalization, and key-derivation operations.

The TypeScript wrappers fail closed when a required native function is unavailable or returns an unexpected shape. Prebuilt native binaries and generated WASM output are not committed.

## Deletion

Deletion is treated as storage lifecycle work across related stores rather than only as hidden route or UI state. The repository includes the selected purge and lifecycle boundaries used for that work.

## Checking the source

Install the Node dependencies and run the TypeScript check:

```bash
npm install
npm run check
```

The native crates can be checked separately with a Rust toolchain:

```bash
cargo check --manifest-path native/voryx-crypto/Cargo.toml
cargo check --manifest-path native/voryx-crypto-wasm/Cargo.toml
```

`npm run native:build` builds the N-API module and requires the Rust toolchain plus the N-API tooling referenced by the package script.

## Security documentation

The docs are intentionally narrower than the full Voryx Sessions design. They describe only claims that can be tied back to code published here.

- [Protocol specification](docs/PROTOCOL_SPEC.md) — request, replay, session, mailbox, and crypto behavior represented by this snapshot
- [Security properties](docs/SECURITY_PROPERTIES.md) — properties claimed for the included paths, with code references
- [Threat model](docs/THREAT_MODEL.md) — attacker classes, trust boundaries, controls, residual risks, and explicit exclusions
- [Security policy](SECURITY.md) — how to report a vulnerability without putting exploit details in a public issue

No external cryptographic audit is claimed.

## License

The source in this repository is available under the [Apache License 2.0](LICENSE).
