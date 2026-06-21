# ADR-0001: Include SMB 3.1.1 in NEGOTIATE Dialect List

**Status:** Accepted  
**Date:** 2026-06-21

## Context

The initial implementation advertised dialects `[0x0300, 0x0210, 0x0202]` (SMB 3.0, 2.1,
2.0.2). Windows 10/11 clients always include `0x0311` (SMB 3.1.1) as the highest-priority
dialect. The absence of 3.1.1 in the dialect list is a reliable fingerprint that
distinguishes the tool from actual Windows workstation traffic — visible to any NDR with
SMB dialect baselining.

SMB 3.1.1 mandates at least one `NegotiateContext` in the request: `PREAUTH_INTEGRITY_CAPABILITIES`
(MS-SMB2 §2.2.3.1.1). The original implementation omitted it precisely because it adds
complexity, and the comment reflected this: *"Dropped 3.1.1 because it requires Negotiate
Contexts to be OPSEC safe."* That tradeoff was wrong — omitting 3.1.1 is itself the OPSEC
risk.

## Decision

Include `0x0311` as the first dialect in the NEGOTIATE request and append the mandatory
`PREAUTH_INTEGRITY_CAPABILITIES` negotiate context with SHA-512 (`0x0001`) and
`SaltLength = 0` (the correct client value; salt is server-to-client only).

Packet layout after the change:

```
NetBIOS(4) + SMB2 header(64) + body-fixed(36) + dialects(8) + padding(4) + NegCtx(14) = 130 bytes
NegotiateContextOffset = 112  (8-byte aligned from SMB2 header start)
NegotiateContextCount  = 1
```

The `SystemTime` field in the NEGOTIATE response sits at a fixed offset (`body + 40`) that
is unchanged across all SMB2 dialects. The response parser required no modification.

## Consequences

- NEGOTIATE request grows from 110 to 130 bytes — negligible.
- The tool's SMB handshake is now indistinguishable from a Windows 10/11 client at the
  dialect-list level.
- If a future dialect (e.g., SMB 3.1.2) is introduced and becomes the Windows default, the
  dialect list will need updating again. The pattern established here — always match the
  current Windows default — should be maintained.
- The same `build_negotiate_request()` function is shared by both `smb` and `ntlm` sources.
  Both benefit from the fix transparently.
