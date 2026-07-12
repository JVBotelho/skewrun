# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CONTRIBUTING.md` to document the contribution process and testing policy.
- `SECURITY.md` to provide a private vulnerability reporting channel.
- `CHANGELOG.md` to track release notes for future versions.
- CSPRNG-backed, log-normal inter-protocol jitter with exponential backoff on consecutive
  failures, replacing the previous flat uniform jitter band (ADR-0004). New `--jitter-sigma`
  and `--jitter-base-ms` CLI flags; sigma is randomized per invocation to resist parametric
  fingerprinting across engagements.
- OS fingerprint camouflage: outbound TCP/UDP sockets set TTL=128 and disable Nagle
  (`TCP_NODELAY=0`) before the handshake to match Windows client wire behavior, instead of
  the Linux defaults (ADR-0005).
- Per-request randomization of CLDAP attribute ordering to break static packet signatures
  (ADR-0006).

### Changed
- SMB2 NEGOTIATE padding is now sized dynamically instead of a fixed-size array, preventing
  a potential panic if the SMB dialect list changes in the future.

### Fixed
- Kerberos AS-REQ, NTLM, and SMB connections now set the outbound TTL *before* the TCP
  handshake completes (previously it was applied to an already-connected socket, leaving the
  initial SYN packet at the Linux default TTL).
