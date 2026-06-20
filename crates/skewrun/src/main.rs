#![deny(unsafe_code)]

use std::net::ToSocketAddrs;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;

use ad_time::protocols::cldap::CldapSource;
use ad_time::protocols::kerberos::KerberosSource;
use ad_time::protocols::ntlm::NtlmSource;
use ad_time::protocols::ntp::NtpSource;
use ad_time::protocols::smb::SmbSource;
use ad_time::time_src::{format_offset, Orchestrator, TimeSource};
use rand::seq::SliceRandom;

const STEALTH_USERS_POOL: &[&str] = &[
    "admnistrator",
    "administator",
    "admimistrator",
    "amdinistrator",
    "admin1strator",
];

#[derive(Parser, Debug)]
#[command(
    name = "skewrun",
    about = "Query DC time via Kerberos/NTP/SMB and run a command under faketime with the correct offset",
    after_help = "EXAMPLES:\n  skewrun 10.10.10.5 -r CORP.LOCAL -- impacket-getTGT CORP.LOCAL/user:pass\n  skewrun 10.10.10.5 --probe\n  skewrun 10.10.10.5 -r CORP.LOCAL -n"
)]
struct Args {
    /// Target IP or hostname (DC)
    target: String,

    /// Kerberos realm (e.g. CORP.LOCAL). If absent, reads from $KRB5_CONFIG or /etc/krb5.conf.
    /// Kerberos method is skipped if realm cannot be determined.
    #[arg(short, long)]
    realm: Option<String>,

    /// Comma-separated list of time sources in order. Default: cldap,smb,ntp
    #[arg(short, long, default_value = "cldap,smb,ntp")]
    method: String,

    /// Timeout per method in seconds
    #[arg(long, default_value_t = 3)]
    timeout: u64,

    /// Principal name used in the Kerberos AS-REQ probe. A plausible admin typo
    /// (default: random pick from pool) blends into the universal Event 4768/0x6 noise in AD.
    /// Change this if the default is blocked or monitored in the target environment.
    #[arg(long)]
    stealth_user: Option<String>,

    /// Explicit path to the faketime binary. Falls back to $FAKETIME_BIN,
    /// /usr/bin/faketime, PATH lookup (via which), then bare "faketime".
    #[arg(long)]
    faketime_path: Option<String>,

    /// Print handshake details to stderr. Command argv is never logged.
    #[arg(short, long)]
    verbose: bool,

    /// Only calculate and print the offset; do not run a command
    #[arg(short = 'p', long)]
    print_offset: bool,

    /// Skip network probe and use an explicit offset string (e.g. "+3.45s")
    #[arg(short = 'o', long)]
    offset: Option<String>,

    /// Probe all methods and report each offset (useful for recon / honeypot detection)
    #[arg(long)]
    probe: bool,

    /// Command and arguments to run under faketime (everything after --)
    #[arg(last = true)]
    command: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !args.print_offset && !args.probe && args.command.is_empty() {
        anyhow::bail!("provide a command to run (after --), or use --print-offset / --probe");
    }

    let timeout = Duration::from_secs(args.timeout);

    // Resolve target to SocketAddr (use port 0 as placeholder; each module overrides the port).
    let target = format!("{}:0", args.target)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve target '{}'", args.target))?
        .next()
        .with_context(|| format!("no addresses resolved for '{}'", args.target))?;

    let realm = args.realm.or_else(read_realm_from_krb5_conf);

    let stealth_user = args.stealth_user.unwrap_or_else(|| {
        let mut rng = rand::thread_rng();
        STEALTH_USERS_POOL.choose(&mut rng).unwrap().to_string()
    });

    if args.probe {
        return run_probe(
            target,
            realm.as_deref(),
            timeout,
            &args.method,
            &stealth_user,
        );
    }

    let fmt = match args.offset {
        Some(o) => o,
        None => {
            let sources = build_sources(&args.method, realm.as_deref(), &stealth_user);
            let orchestrator = Orchestrator::new(sources, args.verbose);

            let (offset_us, method) = orchestrator.resolve(target, timeout)?;
            let f = format_offset(offset_us);
            if args.verbose {
                eprintln!("[{}] {}", method, f);
            }
            f
        }
    };

    if args.print_offset {
        println!("{}", fmt);
        return Ok(());
    }

    let faketime_bin = resolve_faketime_bin(args.faketime_path.as_deref());
    run_under_faketime(&fmt, &args.command, &faketime_bin)
}

fn run_probe(
    target: std::net::SocketAddr,
    realm: Option<&str>,
    timeout: Duration,
    method_csv: &str,
    stealth_user: &str,
) -> anyhow::Result<()> {
    let sources = build_sources(method_csv, realm, stealth_user);
    let mut any_success = false;

    for src in &sources {
        match src.fetch(target, timeout) {
            Ok(offset_us) => {
                println!("{:<10} {}", src.name(), format_offset(offset_us));
                any_success = true;
            }
            Err(e) => {
                println!("{:<10} FAILED: {}", src.name(), e);
            }
        }
    }

    if !any_success {
        anyhow::bail!("all methods failed");
    }
    Ok(())
}

fn build_sources(
    method_csv: &str,
    realm: Option<&str>,
    stealth_user: &str,
) -> Vec<Box<dyn TimeSource>> {
    let mut sources: Vec<Box<dyn TimeSource>> = Vec::new();

    for method in method_csv.split(',').map(str::trim) {
        match method {
            "kerberos" => {
                sources.push(Box::new(KerberosSource {
                    realm: realm.map(str::to_owned),
                    stealth_user: stealth_user.to_owned(),
                }));
            }
            "cldap" => sources.push(Box::new(CldapSource)),
            "ntlm" => sources.push(Box::new(NtlmSource)),
            "ntp" => sources.push(Box::new(NtpSource)),
            "smb" => sources.push(Box::new(SmbSource)),
            other => eprintln!("[warn] unknown method '{}', ignoring", other),
        }
    }

    sources
}

/// Read `default_realm` from $KRB5_CONFIG or /etc/krb5.conf.
fn read_realm_from_krb5_conf() -> Option<String> {
    let path = std::env::var("KRB5_CONFIG")
        .ok()
        .unwrap_or_else(|| "/etc/krb5.conf".to_string());

    let content = std::fs::read_to_string(&path).ok()?;

    // Look for `default_realm = REALM` under [libdefaults].
    let mut in_libdefaults = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_libdefaults = trimmed == "[libdefaults]";
            continue;
        }
        if in_libdefaults {
            if let Some(rest) = trimmed.strip_prefix("default_realm") {
                if let Some(realm) = rest.trim_start().strip_prefix('=') {
                    let realm = realm.trim().to_string();
                    if !realm.is_empty() {
                        return Some(realm);
                    }
                }
            }
        }
    }
    None
}

/// Resolve the faketime binary path: explicit flag → $FAKETIME_BIN → /usr/bin/faketime
/// → PATH lookup → bare "faketime" (relies on caller's PATH).
fn resolve_faketime_bin(explicit: Option<&str>) -> String {
    if let Some(p) = explicit {
        return p.to_owned();
    }
    if let Ok(p) = std::env::var("FAKETIME_BIN") {
        if std::path::Path::new(&p).exists() {
            return p;
        }
        eprintln!("[warn] FAKETIME_BIN={:?} does not exist, searching PATH", p);
    }
    let fixed = "/usr/bin/faketime";
    if std::path::Path::new(fixed).exists() {
        return fixed.to_owned();
    }
    if let Ok(p) = which::which("faketime") {
        return p.to_string_lossy().into_owned();
    }
    "faketime".to_owned()
}

fn run_under_faketime(offset_fmt: &str, command: &[String], bin: &str) -> anyhow::Result<()> {
    let cmd_bin = &command[0];
    let cmd_args = &command[1..];

    // OPSEC / UX: Warn if the target binary is statically linked.
    // LD_PRELOAD (faketime) often fails on static binaries (like Go) that bypass libc.
    if let Ok(file_out) = Command::new("file").arg(cmd_bin).output() {
        let out_str = String::from_utf8_lossy(&file_out.stdout);
        if out_str.contains("statically linked") {
            eprintln!(
                "[warn] target '{}' appears to be statically linked.",
                cmd_bin
            );
            eprintln!("       LD_PRELOAD (faketime) may have no effect if the binary bypasses");
            eprintln!("       libc time syscalls (common in Go-built tools).");
        }
    }

    let status = Command::new(bin)
        .arg("-f")
        .arg(offset_fmt)
        .arg(cmd_bin)
        .args(cmd_args)
        .status()
        .with_context(|| format!("failed to spawn faketime ({bin}) — is libfaketime installed? (apt install faketime / pacman -S libfaketime)"))?;

    #[cfg(unix)]
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    #[cfg(not(unix))]
    let code = status.code().unwrap_or(1);

    std::process::exit(code);
}
