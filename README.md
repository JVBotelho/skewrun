# Skewrun

[![CI](https://github.com/JVBotelho/skewrun/actions/workflows/ci.yml/badge.svg)](https://github.com/JVBotelho/skewrun/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/skewrun.svg)](https://crates.io/crates/skewrun)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13512/badge)](https://www.bestpractices.dev/projects/13512)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JVBotelho/skewrun/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/skewrun)

`skewrun` is an Active Directory time discovery toolkit for red teams. It dynamically resolves the Domain Controller's time via network protocols (CLDAP, SMB, NTP, Kerberos, NTLM) and executes commands via `libfaketime` (`LD_PRELOAD`), tricking the executed binary into using the exact DC time.

This solves the Kerberos `KRB_AP_ERR_SKEW` (Clock Skew Too Great) error, allowing you to run tools like Impacket or NetExec from a Linux attack machine whose clock is heavily desynchronized from the target Windows domain, **without requiring root privileges to change the system time**.

## Architecture: Library-First

Starting with `v0.9.0`, Skewrun is built as a library-first architecture:
- **`ad-time`**: A pure Rust library crate that extracts time from AD protocols stealthily. It can be natively embedded into other Rust implants or tools.
- **`skewrun`**: A CLI binary that orchestrates the `ad-time` library and wraps target processes with `libfaketime`.

## Installation

```bash
# Pre-built static binary (no Rust toolchain required)
wget https://github.com/JVBotelho/skewrun/releases/latest/download/skewrun-x86_64-linux-musl
chmod +x skewrun-x86_64-linux-musl
sudo mv skewrun-x86_64-linux-musl /usr/local/bin/skewrun

# From crates.io
cargo install skewrun

# From source
git clone https://github.com/JVBotelho/skewrun && cd skewrun && cargo build --release
```

*Note: You must have `libfaketime` installed on your system (e.g., `apt-get install libfaketime`).*

## Usage

```bash
# Default behavior (tries CLDAP -> SMB -> NTP)
skewrun 10.10.10.100 -- impacket-getTGT -dc-ip 10.10.10.100 domain.local/user:pass

# Force specific methods
skewrun 10.10.10.100 -m cldap,ntlm,kerberos -- netexec smb 10.10.10.100

# Just print the offset (useful for shell scripting)
skewrun 10.10.10.100 --print-offset

# Offline mode: supply a known offset manually
skewrun --offset "+3.450s" -- impacket-getTGT ...

# Tune inter-method jitter (default: sigma=0.4, base=8000ms; sigma=0 disables jitter)
skewrun 10.10.10.100 --jitter-sigma 0.2 --jitter-base-ms 5000 -- impacket-getTGT ...
```

## Using as a library

```rust
use ad_time::protocols::cldap::CldapSource;
use ad_time::time_src::TimeSource;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let src = CldapSource;
    let addr = "10.10.10.100:389".parse()?;
    let offset_us = src.fetch(addr, Duration::from_secs(3))?;
    println!("DC offset: {} µs", offset_us);
    Ok(())
}
```

Each protocol module (`kerberos`, `ntlm`, `cldap`, `smb`, `ntp`) is independent and extractable for use in custom red team tooling.

## How It Works

Skewrun queries the DC to calculate the exact microsecond offset `(DC_Time - Local_Time)`. It then sets the `FAKETIME` environment variable and injects `libfaketime` into the target command using `LD_PRELOAD`.

### FAKETIME limitations (Static Binaries)
`LD_PRELOAD` relies on intercepting `libc` dynamically linked calls (like `clock_gettime`). If you attempt to use `skewrun` on a **statically compiled binary** (such as many Go or Rust tools), `libfaketime` will silently fail to hook the time functions. Skewrun will warn you if it detects you are attempting to run a static binary.

## Forensic Noise & Evasion

The goal is to blend in with standard Windows wire traffic and minimize forensic footprint on the DC.

Independent of which method is used: every outbound socket sets TTL=128 and enables Nagle
(`TCP_NODELAY=0`) *before* the TCP handshake, matching a Windows client's network-stack
fingerprint instead of the Linux defaults (TTL=64, Nagle off) that a passive observer (p0f,
Zeek `conn.log`) would otherwise flag. Delays between methods use CSPRNG-backed log-normal
jitter (not a flat random range) with exponential backoff on repeated failures, avoiding the
uniform-timing signature a fixed jitter band leaves in connection logs — see `--jitter-sigma`
and `--jitter-base-ms` above.

| Method | Protocol | Port | OPSEC Notes (EDR/NDR Visibility) |
|--------|----------|------|-----------------------------------|
| **cldap** (Default) | CLDAP | UDP/389 | **Extremely Stealthy**. Universally allowed. Sends a standard LDAP `rootDSE` diagnostic query (`objectClass=*` base search), matching the baseline of `ldapsearch`, PowerShell AD cmdlets, and monitoring tools. Dilutes the attribute list with common admin attrs and randomizes the attribute order per request to break static NDR signatures. |
| **smb** (Default) | SMB2 | TCP/445 | **Stealthy**. Extracts time from the `SMB2 NEGOTIATE` response. Negotiates SMB 3.1.1 with `PREAUTH_INTEGRITY_CAPABILITIES` (SHA-512), matching Windows 10/11 client behavior. |
| **ntp** (Default) | SNTP | UDP/123 | **Standard**. Native RFC 4330. Highly expected traffic from any client. |
| **ntlm** | SMB2 | TCP/445 | **Stealthy**. Exploits `SMB2 SESSION_SETUP` to get an NTLM Type 2 Challenge containing `MsvAvTimestamp`. Disconnects TCP before Type 3, meaning **no Event ID 4625 (Logon Failure) is generated**. Emulates Windows 10/11 flags. |
| **kerberos** | Kerberos | TCP/88 | **Loud**. Sends an `AS-REQ` for a non-existent user. Encodes proper two-component `sname`, rotates `cname` (typos like *admnistrator*), sets `till` to the Windows hardcoded constant `20370913024805Z` (not local clock arithmetic — see ADR-0002), randomizes `nonce`. Always generates Event 4768/0x6 (pre-authentication failure for unknown principal) which is exported to SIEM regardless of audit policy. May trigger honey-account alerts if the `cname` matches a configured tripwire. |

## Testing

```bash
cargo test                                            # unit + property tests
cargo +nightly fuzz run fuzz_parse_krb_error          # Linux/macOS only
```

All network-facing parsers (`parse_krb_error`, `parse_cldap_search_response`, `parse_ntlm_type2`,
`parse_negotiate_response`, `parse_ntp_timestamp`) are property-tested for panic safety using
[proptest](https://github.com/proptest-rs/proptest) and fuzz-tested in CI.
BER integer encoding is verified for DER minimality and sign correctness across the full `i32` range,
covering negative etype values per RFC 4120.
Fuzz targets and corpus live in `fuzz/`.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
