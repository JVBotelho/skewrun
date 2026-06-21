# ADR-0002: Kerberos AS-REQ `till` as Windows Hardcoded Constant

**Status:** Accepted  
**Date:** 2026-06-21

## Context

The initial implementation computed `till = now_local + 10h ± 30min jitter`. The intent
was to request a ticket with the default AD lifetime (10 hours) and add jitter to avoid
static periodicity signatures.

This approach had two compounding problems:

**1. Functional correctness — clock dependency**

`now_local` is the attacker machine's clock. This tool exists precisely because that clock
is heavily desynchronized from the domain (minutes to months off). When the local clock is
behind:

```
till = now_local + 10h = (DC_now - Δ) + 10h
```

If `Δ > 10h`, the `till` timestamp is in the past from the DC's perspective. RFC 4120 §3.1.3
specifies that the KDC returns `KDC_ERR_NEVER_VALID` when the requested ticket lifetime is
less than the site-defined minimum. A `till` in the past satisfies this condition. The tool
would fail to receive the `KRB-ERROR` with `stime/susec` needed to compute the offset —
the exact outcome it is designed to avoid.

**2. OPSEC — Windows does not compute `now + 10h`**

Packet captures of real Windows 10/Server 2019-2022 AS-REQ traffic show a hardcoded
far-future constant for `till`, not a computed value. The constant is:

```
20370913024805Z   (September 13, 2037 at 02:48:05 UTC)
```

This value originates from the Windows 2003 Kerberos implementation and corresponds to
`INT32_MAX` seconds minus a safety margin (pre-Y2038 boundary). The KDC ignores the client's
requested `till` entirely and enforces the realm's ticket lifetime policy (RFC 4120 §3.3.2).

The ±30min jitter produced values like `9h43m` or `10h17m` — not a pattern seen in any
legitimate Windows client. This was a self-generated signature with no documented baseline.

Windows 11 22H2+ shifted to a different constant (`99990913024805Z`, year 9999), confirmed
by Heimdal compatibility issues (heimdal/heimdal#1011) and FalconForce detection research.

## Decision

Replace the clock-arithmetic approach with the hardcoded constant:

```rust
fn kerberos_time_plausible_future() -> String {
    "20370913024805Z".to_string()
}
```

The 2037 constant is used (not the 9999 variant) because it covers the broader installed
baseline: Windows 10, Windows 11 pre-22H2, and all current Server versions. Windows 11 22H2+
is a minority of enterprise DCs and clients as of mid-2026.

## Consequences

- Eliminates the functional failure mode where `till` falls in the past on heavily
  desynchronized attack machines.
- AS-REQ `till` field is now indistinguishable from Windows 10/Server 2019-2022 clients.
- Removed ~20 lines of dead datetime arithmetic (`format_unix_as_kerberos_time`,
  `days_to_civil`, jitter logic) and the `UNIX_EPOCH` import.
- If Windows 11 22H2+ becomes the dominant baseline, `till` should be updated to
  `"99990913024805Z"` or exposed as a flag for the operator to choose.
