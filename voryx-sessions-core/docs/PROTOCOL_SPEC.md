# Protocol Specification

## Scope

Voryx Sessions is a key-scoped session system for encrypted messaging and encrypted file exchange.

This document covers only protocol surfaces represented by the source in this repository. It is not a specification of the complete application or deployment.

## Message envelopes

Message payloads are versioned.

The envelope families referenced by the selected source are:

- `v8r` — encrypted message envelope
- `v9pq` — hybrid message envelope

File-envelope handling belongs to code outside this repository and is not specified here.

## Signed requests

Guarded requests bind the signature to:

- timestamp
- nonce
- HTTP method
- normalized path
- request-body hash
- key ID
- public key

The body is hashed independently before the signed payload is verified.

A signed request can be rejected because of a stale timestamp, body-hash mismatch, invalid signature, or consumed nonce.

Relevant code:

- `server/route-modules/request-auth.ts`
- `server/crypto-canonical.ts`
- `server/signature-verification.ts`
- `server/request-nonce-store.ts`

## Replay state

Request nonces are stored under both a scoped key and a key-global nonce key.

The included store supports:

- in-memory state for a single process
- PostgreSQL-backed state for shared runtime state

PostgreSQL consumption is performed transactionally. Both nonce rows must be inserted for the request to be accepted.

## Session access

Session participation, message access, and creator-only access are separate checks.

A participant can be admitted to a session while message access remains locked until the required passphrase grant state is present.

Creator checks are derived from session-scoped participant identity rather than a generic global identity shortcut.

Relevant code:

- `server/route-modules/session-access-guards.ts`
- `server/storage/session-access-policy.ts`

## Mailbox planes

Mailbox access uses scoped capability state.

The selected code separates message-plane state from the rest of session authorization and validates mailbox use against the current session and key context.

Relevant code:

- `server/route-modules/mailbox-plane-state.ts`
- `server/route-modules/mailbox-message.ts`
- `server/mailbox-plane-store.ts`
- `server/route-modules/mailbox-message-idempotency.ts`

## Cryptographic boundary

The TypeScript layer delegates selected cryptographic operations to Rust.

The included boundary exposes operations for:

- Ed25519 signing and verification
- secure random bytes
- constant-time equality
- HKDF-SHA-256
- AES-256-GCM
- SHA-256
- canonical signed payloads
- opaque indexes
- commitments
- nullifiers
- proof hashes

The TypeScript wrappers reject the operation when the expected native result is unavailable or malformed.

Relevant code:

- `server/native/crypto-native.ts`
- `server/crypto-primitives.ts`
- `server/crypto-canonical.ts`
- `native/voryx-crypto/src/lib.rs`
- `native/voryx-crypto-wasm/src/lib.rs`

## Failure behavior

Selected guarded paths stop on conditions including:

- stale signed requests
- replayed nonces
- mismatched request-body hashes
- invalid signatures
- invalid session membership
- missing message-access grant state
- invalid mailbox scope or state
- unavailable required native cryptography

## Limits

This repository does not independently establish the behavior of the full client, transport stack, deployment environment, complete persistence layer, or every protocol route in Sessions.
