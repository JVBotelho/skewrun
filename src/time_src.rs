use std::net::SocketAddr;
use std::time::Duration;

/// Signed offset in microseconds: server_time - local_time.
/// Positive means the server is ahead of us.
pub type OffsetMicros = i64;

#[derive(Debug, thiserror::Error)]
pub enum TimeSourceError {
    #[error("connection timed out")]
    Timeout,
    #[error("connection refused")]
    Refused,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("parse error: {0}")]
    Parse(String),
}

pub trait TimeSource {
    fn name(&self) -> &'static str;
    fn fetch(&self, target: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError>;
}

pub struct Orchestrator {
    sources: Vec<Box<dyn TimeSource>>,
    verbose: bool,
}

impl Orchestrator {
    pub fn new(sources: Vec<Box<dyn TimeSource>>, verbose: bool) -> Self {
        Self { sources, verbose }
    }

    /// Try each source in order; return first success with the method name.
    pub fn resolve(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<(OffsetMicros, &'static str)> {
        let mut last_err: Option<String> = None;

        for src in &self.sources {
            match src.fetch(target, timeout) {
                Ok(offset) => {
                    if self.verbose {
                        eprintln!("[{}] offset = {}", src.name(), format_offset(offset));
                    }
                    return Ok((offset, src.name()));
                }
                Err(e) => {
                    if self.verbose || matches!(e, TimeSourceError::Protocol(_) | TimeSourceError::Parse(_)) {
                        eprintln!("[{}] failed: {}", src.name(), e);
                    }
                    last_err = Some(format!("{}: {}", src.name(), e));
                }
            }
        }

        anyhow::bail!(
            "all time sources failed. Last error: {}",
            last_err.unwrap_or_else(|| "no sources configured".into())
        )
    }
}

/// Format offset as "+3.456789s" or "-0.012345s".
pub fn format_offset(offset_us: OffsetMicros) -> String {
    let sign = if offset_us >= 0 { "+" } else { "-" };
    let abs = offset_us.unsigned_abs();
    format!("{}{}.{:06}s", sign, abs / 1_000_000, abs % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_positive() {
        assert_eq!(format_offset(3_456_789), "+3.456789s");
    }

    #[test]
    fn format_negative() {
        assert_eq!(format_offset(-12_345), "-0.012345s");
    }

    #[test]
    fn format_zero() {
        assert_eq!(format_offset(0), "+0.000000s");
    }
}
