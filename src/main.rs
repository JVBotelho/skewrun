#![deny(unsafe_code)]

use std::net::ToSocketAddrs;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;

mod kerberos;
mod ntp;
mod smb;
mod time_src;

use kerberos::KerberosSource;
use ntp::NtpSource;
use smb::SmbSource;
use time_src::{format_offset, Orchestrator, TimeSource};

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

    /// Comma-separated list of time sources in order. Default: kerberos,ntp,smb
    #[arg(short, long, default_value = "kerberos,ntp,smb")]
    method: String,

    /// Timeout per method in seconds
    #[arg(long, default_value_t = 3)]
    timeout: u64,

    /// Print handshake details to stderr. Command argv is never logged.
    #[arg(short, long)]
    verbose: bool,

    /// Only calculate and print offset; do not run command
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Probe all methods and report each offset (useful for recon / honeypot detection)
    #[arg(long)]
    probe: bool,

    /// Command and arguments to run under faketime (everything after --)
    #[arg(last = true)]
    command: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !args.dry_run && !args.probe && args.command.is_empty() {
        anyhow::bail!("provide a command to run (after --), or use --dry-run / --probe");
    }

    let timeout = Duration::from_secs(args.timeout);

    // Resolve target to SocketAddr (use port 0 as placeholder; each module overrides the port).
    let target = format!("{}:0", args.target)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve target '{}'", args.target))?
        .next()
        .with_context(|| format!("no addresses resolved for '{}'", args.target))?;

    let realm = args.realm.or_else(read_realm_from_krb5_conf);

    if args.probe {
        return run_probe(target, realm.as_deref(), timeout, &args.method);
    }

    let sources = build_sources(&args.method, realm.as_deref());
    let orchestrator = Orchestrator::new(sources, args.verbose);

    let (offset_us, method) = orchestrator.resolve(target, timeout)?;
    let fmt = format_offset(offset_us);

    eprintln!("[{}] {}", method, fmt);

    if args.dry_run {
        return Ok(());
    }

    run_under_faketime(&fmt, &args.command)
}

fn run_probe(
    target: std::net::SocketAddr,
    realm: Option<&str>,
    timeout: Duration,
    method_csv: &str,
) -> anyhow::Result<()> {
    let sources = build_sources(method_csv, realm);
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

fn build_sources(method_csv: &str, realm: Option<&str>) -> Vec<Box<dyn TimeSource>> {
    let mut sources: Vec<Box<dyn TimeSource>> = Vec::new();

    for method in method_csv.split(',').map(str::trim) {
        match method {
            "kerberos" => {
                if let Some(r) = realm {
                    sources.push(Box::new(KerberosSource { realm: r.to_owned() }));
                }
                // If no realm, silently skip Kerberos.
            }
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

fn run_under_faketime(offset_fmt: &str, command: &[String]) -> anyhow::Result<()> {
    let cmd_bin = &command[0];
    let cmd_args = &command[1..];

    let status = Command::new("faketime")
        .arg("-f")
        .arg(offset_fmt)
        .arg(cmd_bin)
        .args(cmd_args)
        .status()
        .with_context(|| "failed to spawn faketime — is libfaketime installed? (apt install faketime / pacman -S libfaketime)")?;

    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));

    std::process::exit(code);
}
