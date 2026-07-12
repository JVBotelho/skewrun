# ADR-0005: OS Fingerprint Camouflage — TTL, TCP Options, SMB Capability Rotation

**Status:** Accepted
**Date:** 2026-07-12

## Context

Skewrun runs on the operator's Linux attack machine. Every packet it sends carries Linux OS
fingerprints at multiple layers of the network stack, visible to Zeek protocol analyzers,
Suricata IDS rules, and SIEM correlation (Splunk, Wazuh) that ingest Zeek `conn.log` data:

| Layer | Linux Default | Windows Default | Detectable By |
|-------|--------------|-----------------|---------------|
| **IP TTL** | 64 | 128 | `conn.log` field `orig_ip_bytes` TTL extrapolation, passive OS fingerprinting (p0f, Ettercap) |
| **TCP ISN** | Cryptographic random (secure_tcp_seq) | Hash-based sequential (per-connection) | `conn.log` ISN entropy analysis |
| **IP ToS/DSCP** | Varies (often 0x00 or 0x10) | 0x00 (Best Effort) | Packet-level IDS rules |
| **TCP_NODELAY** | Disabled by default (Nagle on) — same as Windows | Nagle's algorithm enabled (TCP_NODELAY=0) | Timing analysis of small-packet bursts |
| **TCP Window Scale** | Kernel-tuned (varies) | 8 (256x window scaling) | `conn.log` `window` field |
| **SMB2 Capabilities** | Fixed in code as `0x0000007F` | Varies by Windows build | Zeek SMB analyzer signature matching |

A single packet from a Linux machine (TTL=64) to DC port 445 (SMB) is trivially flagged as
anomalous by any SIEM rule that correlates OS fingerprint with destination: *"Source IP
10.x.x.x identified as Linux (TTL=64), connecting to DC SMB service. Investigate."*

Zeek's `conn.log` records the TTL observed at the sensor. If the sensor is on a SPAN port
within the same L3 segment, TTL degradation is ≤1, so the original TTL is directly visible.

**What we can and cannot spoof:**

- **TTL**: Trivially set via `setsockopt(IPPROTO_IP, IP_TTL, 128)` on both TCP and UDP
  sockets. Standard POSIX.
- **IP ToS**: `setsockopt(IPPROTO_IP, IP_TOS, 0x00)`. Windows default.
- **TCP_NODELAY**: `setsockopt(IPPROTO_TCP, TCP_NODELAY, 0)`. Disables Nagle off.
- **TCP ISN**: Requires raw sockets (`SOCK_RAW` + `IPPROTO_RAW`) or a kernel module.
  Raw sockets require `CAP_NET_RAW` (root). This is **not worth the complexity** — the
  operator would need to run skewrun as root, which is a worse OPSEC trade-off than
  leaving ISN as Linux-default.
- **TCP Window Scale**: Requires `setsockopt(IPPROTO_TCP, TCP_WINDOW_CLAMP, ...)`.
  However, window scale is negotiated during the 3-way handshake and is kernel-managed;
  non-root processes cannot fully override it on Linux. **Out of scope.**

### SMB2 Capability Bit Rotation

The current code advertises a fixed capability set:

```rust
const SMB2_GLOBAL_CAPABILITIES: u32 = 0x0000007F;
// DFS | LEASING | LARGE_MTU | MULTI_CHANNEL |
// PERSISTENT_HANDLES | DIR_LEASING | ENCRYPTION
```

While this is correct for modern Windows builds, a fixed constant used in every NEGOTIATE
request becomes a static signature. Network monitors with SMB protocol analysis (Zeek's
`smb_mapping.log`) can fingerprint the tool by the exact capability bits.

Rotating through a set of legitimate Windows build-specific capabilities breaks this
signature. Each build has a known capability set:

| Windows Build | Capability Bits |
|---------------|----------------|
| Win10 20H1 (19041) | 0x0000007F |
| Win11 22H2 (22621) | 0x0000007F (same, encryption mandatory) |
| Win Server 2022 | 0x0000007F |
| Win Server 2019 | 0x0000007F |

All modern Windows builds share the same capability bits. Diversity comes from **which
dialects they advertise** (already covered by ADR-0001). SMB capability rotation provides
negligible additional stealth and is **rejected** for the capability bits themselves.

## Decision

### 1. Set TTL to 128 on all outbound sockets

Create a `socket_opts` module in `crates/ad-time/src/protocols/` with two functions:

```rust
use std::net::{TcpStream, UdpSocket};

const WINDOWS_TTL: u32 = 128;
const WINDOWS_TOS: u32 = 0;

pub fn set_windows_tcp_opts(stream: &TcpStream) -> io::Result<()> {
    stream.set_ttl(WINDOWS_TTL)?;
    stream.set_nodelay(false)?; // Enable Nagle
    unsafe {
        let fd = stream.as_raw_fd();
        let val: libc::c_int = WINDOWS_TOS;
        libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_TOS, ...);
    }
}

pub fn set_windows_udp_opts(socket: &UdpSocket) -> io::Result<()> {
    socket.set_ttl(WINDOWS_TTL)?;
    unsafe { /* IP_TOS on UDP */ }
}
```

Applied after `TcpStream::connect()` or `UdpSocket::connect()` in every protocol module.

### 2. Reject TCP ISN spoofing

Requires `CAP_NET_RAW` (root) and raw sockets. The OPSEC cost of running skewrun as root
outweighs the fingerprint concealment benefit. The operator's machine TTL is already the
primary OS identifier; fixing that is estimated to eliminate the large majority of passive OS
fingerprinting exposure (an engineering judgment, not a measured figure — TTL is the
cheapest, most commonly checked signal in p0f/Ettercap-style passive fingerprinting, but no
before/after detection-rate measurement has been done).

### 3. Reject SMB2 capability bit rotation

All modern Windows builds use the same `0x7F` capabilities. Rotation would have zero
entropy — the tool would loop through the same constant.

## Consequences

- **`ad-time` library crate** gains `socket_opts.rs`. TCP connections are created via
  `connect_tcp_with_ttl()`: a `socket2::Socket` is created, TTL (or IPv6 unicast hops) and
  Nagle are set on the raw socket, then `Socket::connect_timeout()` completes the 3-way
  handshake — all before the socket is converted to `std::net::TcpStream`. This replaces
  the old `TcpStream::connect_timeout()` + post-connect `set_ttl()` pattern, which left the
  SYN packet at the Linux default TTL=64.
  UDP connections call `set_windows_ttl_udp()` (uses `socket2::SockRef` for per-family
  `set_ttl` / `set_unicast_hops_v6`) before the first send.
- **New dependency**: `socket2 = "0.5"`. `libc` was considered in an earlier iteration
  (for manual `poll` in a non-blocking connect loop) but was removed when the implementation
  switched to `Socket::connect_timeout()`, which handles `EINPROGRESS` correctly in its
  internal poll. The library has zero `unsafe` blocks — `socket2` wraps all FFI safely.
- **IPv6**: both `connect_tcp_with_ttl()` and `set_windows_ttl_udp()` branch on address
  family: `set_ttl(WINDOWS_TTL)` for IPv4, `set_unicast_hops_v6(WINDOWS_TTL)` for IPv6.
  `std::net::set_ttl()` does NOT dispatch to `IPV6_UNICAST_HOPS` on Linux (it's a no-op —
  rust-lang/rust#47727), so the per-family branch is mandatory for correct IPv6 behavior.
- **Protocol modules modified**: `smb.rs`, `ntlm.rs`, `kerberos.rs` call
  `connect_tcp_with_ttl()` instead of `TcpStream::connect_timeout()` + post-connect
  `set_ttl()`. `cldap.rs` and `ntp.rs` call `set_windows_ttl_udp()` before the first
  datagram.
