# voryx-sessions-core

Selected source from Voryx Sessions.

This repository exposes a small part of the implementation behind signed request handling, session-scoped authorization, mailbox capabilities, native cryptographic operations, replay state, and deletion lifecycle handling.

It is not the complete Voryx Sessions application. The UI, server bootstrap, deployment configuration, transport stack, and most persistence code are intentionally not included.

## Included

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

Supporting files are included where the selected modules depend on them directly.

## Boundaries

Guarded requests bind the signature to the request method, normalized path, body hash, timestamp, nonce, key ID, and public key.

Nonces are consumed through an in-memory or PostgreSQL-backed store. The PostgreSQL path records scoped and key-global nonce state transactionally.

Session membership and message access are separate checks. A participant can be a valid session member while still lacking access to message state that requires a grant.

Mailbox capabilities are scoped to session, plane, key identity, and lifetime, then checked against current authorization state when used.

Selected cryptographic operations cross a Rust boundary. The TypeScript wrappers fail closed when the required native implementation is unavailable or returns an invalid shape.

Deletion is represented as explicit lifecycle work across related stores rather than only hiding state at the route layer.

## Native crypto

The native source included here contains selected Ed25519, HKDF-SHA-256, AES-256-GCM, SHA-256, constant-time comparison, canonicalization, and key-derivation operations.

Prebuilt native binaries and generated WASM output are not included.

## Build surface

The TypeScript tree keeps the original module boundaries where practical.

This repository is a source snapshot, not a standalone Sessions server. It has no application entry point or deployment profile.

`npm run check` checks the published TypeScript surface after dependencies are installed. Native builds require a Rust toolchain and the N-API build tooling referenced by the package script.

## Security notes

The code is published to make specific implementation choices inspectable. It is not presented as an audit, a proof of the complete system, or a claim that unpublished modules inherit the same properties.

See:

- [Protocol specification](docs/PROTOCOL_SPEC.md)
- [Security properties](docs/SECURITY_PROPERTIES.md)
- [Threat model](docs/THREAT_MODEL.md)

## Status

Curated source from an active project.

No external cryptographic audit is claimed.
