# skewrun

[![CI](https://github.com/joaov-botelho/skewrun/actions/workflows/ci.yml/badge.svg)](https://github.com/joaov-botelho/skewrun/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Queries a target server's clock via **Kerberos → NTP → SMB** (in that order, with automatic fallback) and runs a command under [`libfaketime`](https://github.com/wolfcw/libfaketime) with the correct time offset.

Built for Active Directory pentest workflows where `KRB_AP_ERR_SKEW` blocks Kerberos auth because your attacker clock diverges from the DC by more than 5 minutes.

---

## Why not `ntpdate`?

| | `ntpdate` + bash | `faketime-ad` | **skewrun** |
|---|---|---|---|
| Time source | NTP only | SMB via nmap | Kerberos · NTP · SMB |
| External deps | `ntpdate` binary | `nmap` | none (beyond `faketime`) |
| Binary | bash script | bash script | static musl binary |
| Fallback | no | no | automatic |
| NTP blocked? | fails | works | Kerberos first; SMB fallback |
| SMB port closed? | works | fails | falls back to Kerberos/NTP |

---

## Install

### Download a pre-built static binary

```
wget https://github.com/joaov-botelho/skewrun/releases/latest/download/skewrun-x86_64-linux
chmod +x skewrun-x86_64-linux && sudo mv skewrun-x86_64-linux /usr/local/bin/skewrun
```

### Build from source

```
git clone https://github.com/joaov-botelho/skewrun
cd skewrun
cargo build --release
```

#### Static musl binary (portable across distros)

```
# Install musl target
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools   # or: pacman -S musl

cargo build --release --target x86_64-unknown-linux-musl
# Binary at: target/x86_64-unknown-linux-musl/release/skewrun
```

#### Prerequisite: libfaketime

```
# Kali / Debian / Ubuntu
sudo apt install faketime

# Arch
sudo pacman -S libfaketime

# Fedora
sudo dnf install libfaketime
```

---

## Usage

```
skewrun [OPTIONS] <TARGET> -- <COMMAND>...
```

```
ARGS:
  <TARGET>           IP or hostname of the DC / target server
  <COMMAND>...       Command and arguments to run (everything after --)

OPTIONS:
  -r, --realm <R>    Kerberos realm (e.g. CORP.LOCAL)
                     Falls back to $KRB5_CONFIG / /etc/krb5.conf if absent
  -m, --method <M>   Comma-separated source order. Default: kerberos,ntp,smb
      --timeout <S>  Per-method timeout in seconds. Default: 3
  -v, --verbose      Show handshake details on stderr
  -n, --dry-run      Print offset only; do not run command
      --probe        Try all methods and print each offset (recon / sanity check)
  -h, --help         Print help
```

### Examples

```bash
# Typical AD workflow — impacket tool with Kerberos auth
skewrun 10.10.10.5 -r CORP.LOCAL -- impacket-getTGT CORP.LOCAL/svc_account:Password1

# Equivalent with BloodHound.py
skewrun 10.10.10.5 -r CORP.LOCAL -- bloodhound-python -c All -u alice -p 'P@ss' -d corp.local -dc 10.10.10.5

# Probe all methods without running a command (useful for recon)
skewrun 10.10.10.5 --probe

# Dry-run: print the computed offset and faketime format
skewrun 10.10.10.5 -r CORP.LOCAL -n

# Force NTP only (skip Kerberos and SMB)
skewrun 10.10.10.5 -m ntp -- impacket-getTGT ...

# Verbose: shows which method succeeded and the raw offset
skewrun 10.10.10.5 -r CORP.LOCAL -v -- impacket-getTGT ...
```

---

## How it works

1. **Kerberos (primary, stealth)** — Sends a minimal `AS-REQ` for a nonexistent principal. Any KDC responds with a `KRB-ERROR` that includes `stime` (server timestamp) in required fields per RFC 4120. Reads the two fields from the error and computes `offset = server_time - local_midpoint`. Precision: ±RTT/2 (well within the 5-minute Kerberos window). Skipped if `--realm` is not provided and cannot be read from `krb5.conf`.

2. **NTP (fallback 1)** — Standard SNTP mode 3 query (RFC 4330) on UDP/123. Full four-point `((t2-t1)+(t3-t4))/2` offset calculation.

3. **SMB (fallback 2)** — Sends an `SMB2 NEGOTIATE` request (dialects 3.1.1, 3.0, 2.1, 2.0.2) and reads `SystemTime` from the `NEGOTIATE_RESPONSE`. Converts FILETIME to Unix time. Single-point approximation ±RTT/2.

The first successful method wins. The binary passes `faketime -f "+X.XXXXXXs"` (relative offset, time ticks normally) as a transparent wrapper around your command, inheriting stdin/stdout/stderr and propagating the exit code exactly.

---

## OPSEC considerations

| Method | Port | Protocol | What logs in the DC |
|---|---|---|---|
| Kerberos | TCP/88 | Kerberos AS-REQ | Security Event 4768 with `FailureCode: 0x6` (principal unknown) — indistinguishable from a user typo |
| NTP | UDP/123 | SNTP | Typically nothing; Windows NTP service rarely logs client queries |
| SMB | TCP/445 | SMB2 NEGOTIATE | A partial session (no login); may appear in SMB audit logs as an unsigned/anonymous negotiate |

**Credential safety:** `--verbose` never logs your command's argv. If you run `skewrun -v dc -- impacket-getTGT REALM/user:PASSWORD`, the password does not appear in stderr.

**LD_PRELOAD restriction:** `libfaketime` uses `LD_PRELOAD`. The Linux kernel strips `LD_PRELOAD` for setuid/setgid binaries — the offset will be silently ignored. This doesn't affect Python-based tools (impacket, bloodhound-python) or most pentest binaries.

**FAST / armored Kerberos:** If the KDC requires pre-authentication armoring (FAST), the AS-REQ may be rejected without returning a parseable `KRB-ERROR`. `skewrun` will fall back to NTP automatically.

### When NOT to use Kerberos mode

- Environment uses honeypot accounts that alert on any failed Kerberos attempt.
- You want zero network contact with port 88 (use `-m ntp,smb`).

---

## Known limitations

- **Linux only.** `libfaketime` relies on `LD_PRELOAD`; no equivalent on Windows. Windows users: use WSL.
- **IPv4 only** in v1. IPv6 support is planned for v1.1.
- **No Kerberos FAST armoring** for the AS-REQ probe. Falls back to NTP automatically when FAST is enforced.

---

## Building for aarch64

```bash
rustup target add aarch64-unknown-linux-musl
sudo apt install gcc-aarch64-linux-gnu

cat >> ~/.cargo/config.toml <<'EOF'
[target.aarch64-unknown-linux-musl]
linker = "aarch64-linux-gnu-gcc"
EOF

cargo build --release --target aarch64-unknown-linux-musl
```

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
