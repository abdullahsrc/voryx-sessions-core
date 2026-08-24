# Security Properties

## Scope

These properties are limited to behavior that can be traced to source included in this repository.

They are not a security claim for the complete Voryx Sessions application.

## P1 — Signed request integrity

Guarded request signatures bind the method, normalized path, body hash, timestamp, nonce, key ID, and public key.

Relevant code:

- `server/route-modules/request-auth.ts`
- `server/crypto-canonical.ts`
- `server/signature-verification.ts`

## P2 — Replay resistance on signed request paths

A valid signature is not sufficient for acceptance. The nonce must also be consumed successfully.

The included nonce store supports memory and PostgreSQL providers. The PostgreSQL provider inserts scoped and key-global nonce records in one transaction and rejects partial or conflicting insertion.

Relevant code:

- `server/route-modules/request-auth.ts`
- `server/request-nonce-store.ts`
- `server/postgres-schema-lock.ts`

## P3 — Session-scoped authorization

A key must resolve to an active participant in the target session before guarded session access succeeds.

Message access adds a separate grant-state check for non-creator participants.

Relevant code:

- `server/route-modules/session-access-guards.ts`
- `server/storage/session-access-policy.ts`

## P4 — Mailbox capability scoping

Mailbox state is separated by plane and session context and is checked against the active key and current session authorization path before use.

Relevant code:

- `server/route-modules/mailbox-plane-state.ts`
- `server/route-modules/mailbox-message.ts`
- `server/mailbox-plane-store.ts`

## P5 — Fail-closed native cryptographic boundary

Selected cryptographic operations are delegated to Rust.

The TypeScript layer throws when the required native function is unavailable or when returned output does not match the expected shape. It does not silently switch to a second cryptographic implementation for these operations.

Session-local sender scope identifiers are derived through the native, domain-separated SHA-256 opaque-index operation. They use the `ss2_` format; deployments with persisted `ss1_` sender peer IDs must migrate those IDs before enabling this version.

Relevant code:

- `server/native/crypto-native.ts`
- `server/crypto-primitives.ts`
- `server/crypto-canonical.ts`
- `server/storage/session-sender-scope.ts`
- `native/voryx-crypto/src/lib.rs`

## P6 — Timing-safe comparison on selected values

Selected secret-derived comparisons are performed through constant-time operations rather than direct string equality.

Relevant code:

- `server/crypto-primitives.ts`
- `server/storage/session-access-policy.ts`
- `native/voryx-crypto/src/lib.rs`

## P7 — Explicit deletion lifecycle

Deletion is represented as storage lifecycle work rather than only a route response or UI state change.

The selected purge code coordinates session-, message-, task-, identity-, and related lifecycle cleanup through explicit store boundaries.

Relevant code:

- `server/storage/storage-deletion-purge.ts`
- `server/storage/session-lifecycle-store.ts`
- `server/storage/storage-interfaces.ts`

## Limits

This repository does not independently establish:

- complete end-to-end confidentiality
- authorization correctness across every private route
- production transport security
- traffic-analysis resistance
- correctness of persistence implementations not included here
- security of deployment configuration
- formal verification
- external audit coverage
