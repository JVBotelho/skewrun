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
use rand::Rng;

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
    after_help = "EXAMPLES:\n  skewrun 10.10.10.5 -r CORP.LOCAL -- impacket-getTGT CORP.LOCAL/user:pass\n  skewrun 10.10.10.5 --probe"
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
    let target = (&args.target[..], 0)
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

    let mut first = true;
    for src in &sources {
        if !first {
            let jitter_ms: u64 = rand::thread_rng().gen_range(500..=5_000);
            std::thread::sleep(Duration::from_millis(jitter_ms));
        }
        first = false;
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
    read_realm_from_file(&path)
}

fn read_realm_from_file(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
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
    let cmd_bin = command
        .first()
        .ok_or_else(|| anyhow::anyhow!("command is empty"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- build_sources ---

    #[test]
    fn build_sources_default_order() {
        let sources = build_sources("cldap,smb,ntp", None, "test");
        let names: Vec<_> = sources.iter().map(|s| s.name()).collect();
        assert_eq!(names, ["cldap", "smb", "ntp"]);
    }

    #[test]
    fn build_sources_unknown_method_skipped() {
        let sources = build_sources("cldap,bogus,smb", None, "test");
        let names: Vec<_> = sources.iter().map(|s| s.name()).collect();
        assert_eq!(names, ["cldap", "smb"]);
    }

    #[test]
    fn build_sources_all_known_methods() {
        let sources = build_sources("kerberos,cldap,ntlm,ntp,smb", Some("CORP.LOCAL"), "test");
        assert_eq!(sources.len(), 5);
    }

    #[test]
    fn build_sources_empty_csv_yields_no_sources() {
        let sources = build_sources("", None, "test");
        assert_eq!(sources.len(), 0);
    }

    // --- run_under_faketime: F10 regression guard ---

    #[test]
    fn run_under_faketime_empty_command_errors() {
        let result = run_under_faketime("+0s", &[], "faketime");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("command is empty"));
    }

    // --- resolve_faketime_bin: explicit passthrough ---

    #[test]
    fn resolve_faketime_bin_explicit_returned_verbatim() {
        assert_eq!(resolve_faketime_bin(Some("/custom/faketime")), "/custom/faketime");
    }

    // --- read_realm_from_file ---

    struct TempKrb5(std::path::PathBuf);
    impl TempKrb5 {
        fn new(content: &str) -> Self {
            static CTR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = CTR.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("skewrun_krb5_{}.conf", n));
            std::fs::write(&path, content).unwrap();
            TempKrb5(path)
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for TempKrb5 {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn read_realm_from_file_valid() {
        let f = TempKrb5::new("[libdefaults]\n    default_realm = CORP.LOCAL\n");
        assert_eq!(read_realm_from_file(f.path()), Some("CORP.LOCAL".to_string()));
    }

    #[test]
    fn read_realm_from_file_no_libdefaults_section() {
        let f = TempKrb5::new("[realms]\n    CORP.LOCAL = {}\n");
        assert_eq!(read_realm_from_file(f.path()), None);
    }

    #[test]
    fn read_realm_from_file_missing_returns_none() {
        assert_eq!(read_realm_from_file("/nonexistent/skewrun/path.conf"), None);
    }

    #[test]
    fn read_realm_from_file_empty_realm_value_ignored() {
        let f = TempKrb5::new("[libdefaults]\n    default_realm =\n");
        assert_eq!(read_realm_from_file(f.path()), None);
    }
}
