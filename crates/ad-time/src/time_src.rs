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
    #[error("config error: {0}")]
    Config(String),
}

pub trait TimeSource {
    fn name(&self) -> &'static str;
    fn fetch(&self, target: SocketAddr, timeout: Duration)
        -> Result<OffsetMicros, TimeSourceError>;
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("all time sources failed. Last error: {0}")]
    AllSourcesFailed(String),
    #[error("no sources configured")]
    NoSourcesConfigured,
}

pub struct Orchestrator {
    sources: Vec<Box<dyn TimeSource>>,
    verbose: bool,
    sigma: f64,
    base_ms: u64,
}

impl Orchestrator {
    pub fn new(sources: Vec<Box<dyn TimeSource>>, verbose: bool) -> Self {
        Self { sources, verbose, sigma: 0.4, base_ms: 8000 }
    }

    pub fn with_jitter(mut self, sigma: f64, base_ms: u64) -> Self {
        self.sigma = sigma;
        self.base_ms = base_ms;
        self
    }

    /// Try each source in order; return first success with the method name.
    pub fn resolve(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<(OffsetMicros, &'static str), OrchestratorError> {
        let mut last_err: Option<String> = None;
        let mut failures: u32 = 0;

        let n = self.sources.len();
        for (i, src) in self.sources.iter().enumerate() {
            match src.fetch(target, timeout) {
                Ok(offset) => {
                    if self.verbose {
                        eprintln!("[{}] offset = {}", src.name(), format_offset(offset));
                    }
                    return Ok((offset, src.name()));
                }
                Err(e) => {
                    if self.verbose || !matches!(e, TimeSourceError::Config(_)) {
                        eprintln!("[{}] failed: {}", src.name(), e);
                    }
                    last_err = Some(format!("{}: {}", src.name(), e));

                    let is_config = matches!(e, TimeSourceError::Config(_));

                    if !is_config && i + 1 < n {
                        let delay = jittered_delay(self.base_ms, self.sigma, failures);
                        std::thread::sleep(delay);
                    }

                    // Two-tier backoff: timeouts and config errors are environmental
                    // (no response received, or not even attempted) — reset counter.
                    // Refused/Protocol/Parse errors keep incrementing.
                    if matches!(e, TimeSourceError::Timeout | TimeSourceError::Config(_)) {
                        failures = 0;
                    } else {
                        failures += 1;
                    }
                }
            }
        }
        if let Some(err) = last_err {
            Err(OrchestratorError::AllSourcesFailed(err))
        } else {
            Err(OrchestratorError::NoSourcesConfigured)
        }
    }
}

/// Format offset as "+3.456789s" or "-0.012345s".
pub fn format_offset(offset_us: OffsetMicros) -> String {
    let sign = if offset_us >= 0 { "+" } else { "-" };
    let abs = offset_us.unsigned_abs();
    format!("{}{}.{:06}s", sign, abs / 1_000_000, abs % 1_000_000)
}

/// Uniform [0, 1) float from CSPRNG (53-bit mantissa).
pub(crate) fn crypto_uniform_f64() -> f64 {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("CSPRNG failure");
    (u64::from_le_bytes(buf) >> 11) as f64 / (1u64 << 53) as f64
}

/// Log-normal jitter: median == base_ms, spread controlled by sigma.
/// Uses Box-Muller to generate standard normal from two uniform samples.
/// Right tail is heavier than uniform, matching human/background-task timing.
fn lognormal_jitter_ms(base_ms: u64, sigma: f64) -> u64 {
    let u1 = loop {
        let u = crypto_uniform_f64();
        if u > 0.0 {
            break u;
        }
    };
    let u2 = crypto_uniform_f64();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    let factor = (z * sigma).exp();
    if !factor.is_finite() || factor > 1_000_000.0 {
        return u64::MAX; // capped by caller's MAX_DELAY_MS
    }
    (base_ms as f64 * factor).round() as u64
}

/// Exponential backoff: 3^failures, capped at 5 attempts.
fn backoff_multiplier(failures: u32) -> u64 {
    3u64.pow(failures.min(5))
}

/// Absolute maximum delay for any single inter-protocol sleep (30 minutes).
const MAX_DELAY_MS: u64 = 1_800_000;

fn jittered_delay(base_ms: u64, sigma: f64, failures: u32) -> Duration {
    let raw = backoff_multiplier(failures).saturating_mul(lognormal_jitter_ms(base_ms, sigma));
    Duration::from_millis(raw.min(MAX_DELAY_MS))
}

/// Log-normal jitter for diagnostic probe mode: no backoff.
pub fn probe_jitter(sigma: f64, base_ms: u64) -> Duration {
    let raw = if sigma <= 0.0 {
        base_ms
    } else {
        lognormal_jitter_ms(base_ms, sigma)
    };
    Duration::from_millis(raw.min(MAX_DELAY_MS))
}

/// Apply per-invocation randomization to sigma so that the log-normal
/// distribution shape is not fingerprintable across multiple runs.
/// Multiplier is uniform in [0.5, 1.5), centered at 1.0.
pub fn randomize_sigma(sigma: f64) -> f64 {
    if sigma <= 0.0 || !sigma.is_finite() {
        return 0.0;
    }
    let r = 0.5 + crypto_uniform_f64();
    sigma * r
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

    // --- backoff_multiplier ---

    #[test]
    fn backoff_zero_failures_is_one() {
        assert_eq!(backoff_multiplier(0), 1);
    }

    #[test]
    fn backoff_grows_by_powers_of_three() {
        assert_eq!(backoff_multiplier(1), 3);
        assert_eq!(backoff_multiplier(2), 9);
        assert_eq!(backoff_multiplier(3), 27);
    }

    #[test]
    fn backoff_capped_at_five() {
        assert_eq!(backoff_multiplier(5), 243);
        assert_eq!(backoff_multiplier(6), 243);
        assert_eq!(backoff_multiplier(100), 243);
    }

    // --- lognormal_jitter_ms ---

    #[test]
    fn lognormal_jitter_non_negative() {
        for _ in 0..100 {
            let ms = lognormal_jitter_ms(8000, 0.4);
            assert!(ms > 0, "got zero or negative jitter: {}", ms);
        }
    }

    #[test]
    fn lognormal_jitter_zero_sigma_is_deterministic() {
        assert_eq!(lognormal_jitter_ms(8000, 0.0), 8000);
    }

    // --- jittered_delay ---

    #[test]
    fn jittered_delay_never_exceeds_max() {
        for _ in 0..100 {
            let d = jittered_delay(8000, 0.4, 0);
            assert!(d <= Duration::from_millis(MAX_DELAY_MS));
        }
    }

    #[test]
    fn lognormal_jitter_capped_for_large_factor() {
        // With sigma=300, ~52% of Box-Muller samples produce z<0 (tiny delay).
        // Only z>>0 triggers the factor>1e6 guard returning u64::MAX, which
        // jittered_delay's saturating_mul + .min(MAX_DELAY_MS) absorbs safely.
        // The test verifies the safety property: delay never exceeds the cap,
        // regardless of which side of the Box-Muller the RNG lands on.
        for _ in 0..50 {
            let d = jittered_delay(8000, 300.0, 5);
            assert!(
                d <= Duration::from_millis(MAX_DELAY_MS),
                "delay {}s exceeded cap {}s for sigma=300",
                d.as_secs_f64(),
                MAX_DELAY_MS as f64 / 1000.0
            );
        }
    }

    // --- probe_jitter ---

    #[test]
    fn probe_jitter_zero_sigma_returns_base() {
        assert_eq!(probe_jitter(0.0, 500), Duration::from_millis(500));
        assert_eq!(probe_jitter(0.0, 2000), Duration::from_millis(2000));
    }

    #[test]
    fn probe_jitter_nonzero_sigma_respects_base() {
        for _ in 0..20 {
            let d = probe_jitter(0.4, 1000);
            assert!(d > Duration::ZERO);
            assert!(d <= Duration::from_millis(MAX_DELAY_MS));
        }
    }

    // --- crypto_uniform_f64 ---

    #[test]
    fn crypto_uniform_is_in_unit_interval() {
        for _ in 0..200 {
            let v = crypto_uniform_f64();
            assert!(v >= 0.0 && v < 1.0, "out of [0,1): {}", v);
        }
    }

    // --- randomize_sigma ---

    #[test]
    fn randomize_sigma_zero_returns_zero() {
        assert_eq!(randomize_sigma(0.0), 0.0);
    }

    #[test]
    fn randomize_sigma_is_in_expected_range() {
        for _ in 0..100 {
            let s = randomize_sigma(0.4);
            assert!(s >= 0.2 && s < 0.6, "out of [0.2, 0.6): {}", s);
        }
        for _ in 0..100 {
            let s = randomize_sigma(1.0);
            assert!(s >= 0.5 && s < 1.5, "out of [0.5, 1.5): {}", s);
        }
    }
}
