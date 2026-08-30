# Threat Model

## Scope

This threat model is limited to the source published in this repository.

The selected code covers signed request handling, replay state, session authorization, mailbox state, native cryptographic boundaries, and parts of the deletion lifecycle.

## Protected state

The exposed code is concerned with protection of:

- key-scoped request identity
- signed request integrity
- replay state
- session membership state
- passphrase grant state
- mailbox capability state
- selected encrypted state boundaries
- deletion lifecycle state

## Adversaries

The relevant attacker classes include:

- an unauthenticated network caller
- an authenticated key attempting access outside its session scope
- a participant attempting message access without the required grant state
- a caller replaying a previously valid request
- a caller modifying signed request content after signing
- a caller presenting mailbox state outside its intended scope
- a runtime missing a required native cryptographic dependency

## Trust boundaries

### Request boundary

Network input is untrusted.

On guarded paths, timestamp, body hash, signature, and nonce state are checked before the request is accepted.

### Replay boundary

Nonce state can be process-local or PostgreSQL-backed.

A shared runtime requires a shared nonce provider if replay rejection must remain consistent across instances.

### Session boundary

Possession of a valid key does not imply access to every session.

Membership is resolved against the target session. Message access can require additional grant state.

### Mailbox boundary

Mailbox state is scoped capability state, not a permanent authorization grant.

The selected code reuses current session and key authorization when mailbox actions are processed.

### Cryptographic boundary

The TypeScript layer calls a Rust implementation for selected primitives and canonicalization.

Failure to load or validate the required native result stops the operation.

### Storage lifecycle boundary

Deletion is handled inside storage lifecycle code rather than being represented only as a route-level flag.

## Threats and controls

### T1 — Modified signed request

Risk:

A caller changes the request method, path, body, or identity fields after a signature is produced.

Controls:

- canonical signed payload
- body SHA-256 binding
- method and path binding
- key ID and public-key binding
- signature verification

Residual risk:

Compromise of the signing key is outside this control.

### T2 — Replay of a valid request

Risk:

A previously valid signed request is submitted again.

Controls:

- signed timestamp
- configured skew window
- scoped and key-global nonce consumption
- transactional PostgreSQL provider for shared state

Residual risk:

A multi-instance deployment that intentionally uses the in-memory provider does not share replay state between processes.

### T3 — Cross-session access

Risk:

A valid key attempts to act inside a session where it is not an active participant.

Controls:

- target-session lookup
- participant lookup scoped to that session
- creator identity derived from session-scoped participant state

Residual risk:

Correctness still depends on the backing storage implementation used by the full application.

### T4 — Message access without grant state

Risk:

A participant attempts to access message state without the required passphrase grant.

Controls:

- separate message-access guard
- passphrase-state check
- creator-specific path

Residual risk:

A compromised authorized endpoint can expose plaintext available to that endpoint.

### T5 — Mailbox capability used outside scope

Risk:

Mailbox state is reused outside the intended session, plane, key, or validity window.

Controls:

- plane separation
- session-scoped state
- current key validation
- current session authorization checks
- idempotency state on selected message paths

Residual risk:

Some token issuance and transport code remains outside this repository.

### T6 — Silent cryptographic downgrade

Risk:

A required native primitive is unavailable and a different implementation is used without an explicit decision.

Controls:

- explicit Rust boundary
- fail-closed TypeScript wrappers
- output-shape validation on selected native results

Residual risk:

No external cryptographic audit is claimed for the native source.

### T7 — Incomplete deletion

Risk:

A deletion action leaves related state behind.

Controls:

- explicit deletion/purge flow
- separate lifecycle stores
- scoped cleanup operations for related state

Residual risk:

This repository includes only part of the full persistence implementation, so complete deletion behavior cannot be reproduced from this snapshot alone.

## Out of scope

This repository does not claim to solve:

- compromised client endpoints
- global traffic analysis
- malicious infrastructure with complete control
- complete anonymity
- security of unpublished modules
- formal verification of the full protocol

## Audit status

No external cryptographic audit is claimed.
