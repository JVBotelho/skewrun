# ADR-0006: Per-Request Nonce Injection in Protocol Padding and Permissive Fields

**Status:** Accepted
**Date:** 2026-07-12

## Context

Several protocol messages constructed by skewrun contain fields that are either ignored by
the DC parser or have permissive value ranges. These fields are easy targets for per-request
byte-level randomization that breaks static packet signatures.

The technique is inspired by Sliver's `NonceQueryArgument()` function
(`sliver/implant/sliver/transports/httpclient/httpclient.go:63-72`), which injects random
characters into URL query parameters. The same principle applies at a lower level: padding
bytes, optional field order, and permissive protocol constants can be randomized without
functional impact.

### Target fields per protocol

| Protocol | Field | Current | Risk | Action |
|----------|-------|---------|------|--------|
| **CLDAP** | Attribute ordering in `PartialAttributeList` | Fixed order: `[schemaNamingContext, namingContexts, currentTime, dnsHostName, supportedLDAPVersion]` | Static signature. Zeek LDAP analyzer records attribute sequence. | **Accepted.** Randomize order per request via `rand::seq::SliceRandom::shuffle()`. |
| **SMB2** | Padding bytes (4 bytes at offset 108) | Zero-filled (`\x00\x00\x00\x00`) | Static 4-byte zero pattern at a fixed offset. | **Rejected.** MS-SMB2 §2.2.3 "MUST be set to zero." See rejection rationale below. |
| **NTLM** | `MsvAvTimestamp` AV_PAIR position | Always the LAST AvId after target info fields | Predictable TLV ordering. | **Rejected.** Would require restructuring the TLV builder for negligible gain. |
| **NTLM** | `NTLMRevisionCurrent` in Version block | Fixed `0x0F` | Single constant, but alternative values contradict SMB 3.1.1 identity from ADR-0001. | **Rejected.** See rejection rationale below. |
| **NTP** | Reference Timestamp (8 bytes) | Not set (zero) | Static zero field at a fixed position in the 48-byte SNTP packet. | **Rejected.** Every real NTP client sends zero here; non-zero is a stronger signature than zero. See rejection rationale below. |
| **Kerberos** | `nonce` field | Already randomized (`u32` via `rand::rng()`) | Single `u32` is correct per RFC 4120. Additional randomization beyond this is protocol-breaking. | **No action needed.** |

### Out of scope: MsvAvTimestamp position shuffling

Moving the `MsvAvTimestamp` (AvId=7) within the NTLM `AV_PAIR` sequence is technically
valid (MS-NLMP §2.2.2.1 imposes no ordering requirement), but the current implementation
sends exactly 3 AvPairs in a specific order. Reordering would require restructuring the
TLV builder and adds complexity disproportionate to the benefit.

### Rejected: NTLMRevisionCurrent rotation

An earlier version of this ADR proposed randomizing `NTLMRevisionCurrent` among
`[0x0B, 0x0C, 0x0D, 0x0E, 0x0F]` — all five are documented as valid values in MS-NLMP
Appendix B §33. However, those values are not interchangeable in practice: `0x0B`–`0x0E`
correspond to Windows NT/2000/XP/2003 minor revisions, while `0x0F` is what Windows 10/11
actually sends. ADR-0001 already commits this tool's SMB dialect list to advertise `0x0311`
(SMB 3.1.1), which is exclusive to Windows 10/11 — no real client negotiates SMB 3.1.1 and
then reports an NTLM revision from the Windows XP/2003 era in the same session. Rotating
this field would not dilute the fingerprint; it would manufacture an internally inconsistent
one, which is more conspicuous to an analyst cross-referencing both fields than a static
`0x0F` ever was. This is the same failure mode ADR-0005 already identified and rejected for
SMB2 capability rotation (zero real entropy across the values that matter), so the two
decisions are kept consistent: `NTLMRevisionCurrent` stays fixed at `0x0F`.

### Rejected: SMB2 padding CSPRNG

The SMB2 NEGOTIATE request includes 4 bytes of padding between the dialect list and the
negotiate context to achieve 8-byte alignment. MS-SMB2 §2.2.3 explicitly states that
padding bytes "MUST be set to 0 when being sent." Filling them with CSPRNG bytes violates
the spec requirement and is a stronger fingerprint than zero — a negated-match Suricata rule
(`content:!"|00 00 00 00|"; offset:108; depth:4;`) would flag any non-zero values at this
known offset. Practical risk is low (few organizations deploy SMB2 deep-packet inspection
at this level), but the trade-off is not worth it: zero is universal, spec-compliant, and
the baseline from which no SMB client deviates. Padding stays zero.

### Rejected: NTP Reference Timestamp CSPRNG

The NTP Reference Timestamp (bytes 16–23 of the 48-byte SNTP packet) was initially filled
with CSPRNG bytes based on an incorrect reading of RFC 5905 §7.3. The field in mode 3
(client) requests carries no meaning — every real NTP client (Windows, Linux, Cisco IOS/NX-OS)
sends `0x0000000000000000`. Non-zero or non-timestamp values are trivially detectable:
`content:!"|00 00 00 00 00 00 00 00|"; offset:16; depth:8;`. The IETF draft
`draft-ietf-ntp-data-minimization` further recommends always sending zero to prevent
fingerprinting. The field stays zero (the buffer is already zero-initialized).

## Decision

### 1. CLDAP: randomize attribute order

In `crates/ad-time/src/protocols/cldap.rs`, after constructing the attribute list vector,
apply `shuffle()`:

```rust
use rand::seq::SliceRandom;

let mut attrs = vec![...]; // 5 attribute strings
attrs.shuffle(&mut rand::rng());
```

The `BerReader` in the response parser walks all attributes exhaustively and matches
`currentTime` by name, so the order in the request is irrelevant to correctness.

### 2. SMB2: keep padding zero (rejected CSPRNG)

`crates/ad-time/src/protocols/smb_common.rs` keeps the zero-filled padding per
MS-SMB2 §2.2.3. See "Rejected: SMB2 padding CSPRNG" above for rationale. The padding
array is sized dynamically via `vec![0u8; padding_size]` to prevent a bounds panic
if the dialect list ever changes (see ADR-0001).

### 3. NTLM: no change to NTLMRevisionCurrent

`crates/ad-time/src/protocols/ntlm.rs` keeps the fixed `0x0F`. See "Rejected:
NTLMRevisionCurrent rotation" above.

### 4. NTP: keep Reference Timestamp zero (rejected CSPRNG)

`crates/ad-time/src/protocols/ntp.rs` keeps the zero-filled Reference Timestamp.
The buffer is already zero-initialized (`[0u8; 48]`), so no code changes were needed.
See "Rejected: NTP Reference Timestamp CSPRNG" above for rationale.

## Consequences

- **Protocol modules modified**: `cldap.rs` (+1 line for shuffle). `smb_common.rs` received
  a dynamic padding-size fix (`vec!` instead of fixed `[0u8; 4]`) as a latent-bug hardening.
  `ntlm.rs`, `ntp.rs`, and `kerberos.rs` are unchanged.
- **Dependencies**: the `getrandom` dependency added to `ad-time` in the initial
  implementation remains — it is still used by `time_src.rs` (ADR-0004, CSPRNG jitter).
  SMB padding and NTP ref timestamp no longer use it, so no additional syscalls.
- **Detection impact**: only CLDAP attribute order randomization is active. Per-request
  diversity dropped from 3 fields to 1, but the remaining field has high entropy (5! = 120
  permutations) and the rejected fields would have created stronger detection signatures
  than the static values they replaced.
- **Fuzz targets**: all existing fuzzers continue to pass (no parser changes).
- **`deny.toml`**: `getrandom 0.4` (dev-dep only, via `tempfile → proptest`) added to
  skip list with a comment documenting it is never in release binaries.
