# Security

This repository contains security-sensitive code from Voryx Sessions, but it is not the complete application. Reports should be limited to behavior that can be traced to the source published here.

## Reporting a vulnerability

Please do not open a public issue with working exploit details, private keys, credentials, or other sensitive material.

If GitHub private vulnerability reporting is available for this repository, use it. If it is not available, open a minimal issue asking for a private reporting channel and leave out the technical details until a private channel is established.

A useful report includes the affected file or path, the security property you believe is violated, the conditions required to reproduce the problem, and the practical impact. A small reproducer is welcome when it can be shared safely.

## Scope

The published surface covers signed request verification, replay state, session authorization, mailbox capability state, selected native cryptographic operations, and parts of the deletion lifecycle.

The UI, deployment configuration, transport stack, server bootstrap, and most persistence code are outside this repository. A finding that depends entirely on unpublished code cannot be validated from this snapshot.

The current protocol assumptions and claimed properties are documented in:

- [Protocol specification](docs/PROTOCOL_SPEC.md)
- [Security properties](docs/SECURITY_PROPERTIES.md)
- [Threat model](docs/THREAT_MODEL.md)

No bug bounty or response-time commitment is implied by this file.
