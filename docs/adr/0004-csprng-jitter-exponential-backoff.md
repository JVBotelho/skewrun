# ADR-0004: CSPRNG-Based Jitter with Exponential Backoff

**Status:** Accepted
**Date:** 2026-07-12

## Context

The current jitter implementation in both `Orchestrator::resolve()` (inter-method delay via
`rand::rng().random_range(500..=5_000)`) and `run_probe()` uses `rand::rng()` — Rust's
thread-local `StdRng`. This has two problems:

**1. `rand::rng()` uses `ChaCha12Rng`, not a CSPRNG**

`StdRng` is seeded from OS entropy at first call per thread, but the ChaCha12Rng algorithm
itself is not cryptographically secure against state compromise or prediction. If a defender
captures one delay value and recovers the RNG state, all subsequent delays in the same
thread become predictable — enabling IDS rule writers to construct deterministic timing
signatures.

**2. Fixed jitter band = static fingerprint**

The `500..=5_000` millisecond range produces a flat distribution. This is detectable via
statistical analysis of inter-probe intervals in Zeek/Suricata connection logs. Real user
behaviors and Windows automated tasks exhibit log-normal or Pareto-distributed timing, not
uniform random in a narrow fixed band.

**3. No failure-mode adaptation**

On repeated protocol failures (retry across multiple sources), the tool currently applies the
same per-hop jitter. A network monitor observing rapid sequential failures with short,
uniform gaps can identify automated probing. Production C2 frameworks (Havoc, Sliver,
NimPlant) address this via *exponential backoff* — doubling or tripling the sleep interval
on each consecutive failure, capped at a maximum.

### Analysis of C2 Framework Reference Implementations

| Framework | Jitter Type | RNG | Backoff |
|-----------|------------|-----|---------|
| **Havoc** | Percent (0–100%), integer stored in profile. Actual algorithm in C implant (not in teamserver Go source). | Implant C (unknown) | None |
| **NimPlant** | Percent (0.0–1.0 float), `sleepTime ± sleepTime * rand(-jitter, +jitter)` | `rand()` (Nim standard) | Exponential: `3^attempt`, max 5 attempts. Affects both `sleepTime` and `sleepJitter`. |
| **Sliver** | Absolute nanosecond value, `beacon.Interval() + crypto_rand(0, beacon.Jitter())` | `crypto/rand` via custom `Int63n()` with rejection sampling | Dynamic via operator command (`reconfigReq.BeaconJitter`) |

The NimPlant backoff pattern (`3^attempt`) is the most directly applicable to skewrun because:
- It is simple, self-contained, and does not require an operator command loop.
- `3^x` grows fast but not unboundedly; with max 5 attempts, worst case is `3^5 = 243x` the
  base delay.
- Skewrun's orchestration loop (try sources in order, stop on first success) maps directly to
  the retry-until-success model where backoff applies.

The Sliver CSPRNG pattern (`crypto/rand` via rejection sampling in `Int63n`) is the correct
standard: it eliminates bias from the modulus operation (`x % n` when `max_uint64` is not
divisible by `n`) and uses kernel entropy directly.

**Note on scope:** switching the RNG source addresses problem 1 (predictability of a
compromised thread-local state) but not problem 2 (uniform distribution shape). A CSPRNG
sampled uniformly over a range is still statistically uniform — the fix for problem 2 is a
change to the sampling *distribution*, not the entropy source. Both are addressed separately
below (§1 for the source, §2 for the distribution).

**Note on threat model provenance:** the backoff pattern below is imported from C2 frameworks
built for long-running beaconing (days of check-ins to a teamserver), where breaking
inter-beacon interval correlation is the whole point. `skewrun` is a short-lived invocation —
typically 1–3 fallback attempts across a few seconds. The backoff is still worth having (it's
cheap and doesn't hurt), but its actual value against a SIEM correlating a handful of packets
into a single "recon event" is smaller than the C2 literature it's borrowed from would
suggest. Treat it as a low-cost hardening measure, not a proven mitigation for this usage
pattern.

## Decision

### 1. Replace `rand::rng()` with `getrandom` CSPRNG

Add the `getrandom` crate dependency to the `ad-time` library crate and use
`getrandom::fill()` (the CSPRNG output function, renamed from `getrandom::getrandom()`
in v0.3) to generate 64-bit uniform samples for the Box-Muller transform. A
rejection-sampling integer range sampler (`crypto_range`) was described in an earlier
draft of this ADR but was never implemented — the Box-Muller path uses
`crypto_uniform_f64()` directly, which extracts 53 mantissa bits from CSPRNG bytes.
Impact: the `rand` crate remains for protocol nonces/IDs in the library and for
`STEALTH_USERS_POOL.choose()` in the binary. Only jitter timing uses CSPRNG.

### 2. Log-normal jitter instead of a flat percent band

NimPlant/Havoc's percent-jitter model (`base_ms ± base_ms * jitter_pct / 100`) is still a
**uniform** distribution over a band — it does not address the statistical-shape problem
from the Context (real user/task-scheduler timing is log-normal or Pareto, not uniform).
Instead, sample a log-normal multiplier using the same CSPRNG bytes from §1, via a
Box-Muller transform. This keeps the dependency footprint the same (`getrandom` only, no
`rand_distr`) while producing a distribution shape that resists the statistical
distinguishers described above — median delay stays at `base_ms`, but the right tail is
heavier and the left tail compresses, matching human/background-task timing far more closely
than a flat band.

```rust
fn crypto_uniform_f64() -> f64 {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("CSPRNG failure");
    (u64::from_le_bytes(buf) >> 11) as f64 / (1u64 << 53) as f64 // 53 bits -> [0, 1)
}

/// Log-normal jitter: median == base_ms, right-skewed tail (heavier than uniform).
fn lognormal_jitter_ms(base_ms: u64, sigma: f64) -> u64 {
    let u1 = loop { let u = crypto_uniform_f64(); if u > 0.0 { break u; } }; // avoid ln(0)
    let u2 = crypto_uniform_f64();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos(); // standard normal
    (base_ms as f64 * (z * sigma).exp()).round() as u64
}
```

`sigma` defaults to `0.4`: wide enough to break a fixed-band signature, narrow enough that the
common case stays close to `base_ms`. This replaces the percent-jitter formula everywhere it
would otherwise be used.

### 3. Exponential backoff on consecutive failures

Following NimPlant's `3^n` model with a maximum of 5 attempts before the cap:

```rust
fn backoff_multiplier(consecutive_failures: u32) -> u64 {
    3u64.pow(consecutive_failures.min(5))
}
```

This is applied multiplicatively to the base delay:

```
final_delay = backoff_multiplier(failures) * lognormal_jitter_ms(base_ms, sigma)
```

The `Orchestrator` tracks `consecutive_failures` with two-tier semantics:
- **Timeout errors** (network congestion): reset the counter to 0 — environmental, not
  indicative of an active block. The next source gets `3^0 = 1×` backoff.
- **Refused, Protocol, Parse, Config errors**: increment the counter. The next source gets
  `3^failures ×` backoff. The first such error uses `3^0 = 1×` (no backoff on the initial
  failure in a series).

Delay is computed *before* the counter changes, so the failing source's own sleep interval
reflects the state accumulated from prior failures, not its own.

```rust
// Within resolve():
match src.fetch(target, timeout) {
    Err(e) => {
        let is_config = matches!(e, TimeSourceError::Config(_));
        if !is_config && i + 1 < n {
            let delay = jittered_delay(self.base_ms, self.sigma, failures);
            std::thread::sleep(delay);
        }
        if matches!(e, TimeSourceError::Timeout | TimeSourceError::Config(_)) {
            failures = 0;
        } else {
            failures += 1;
        }
    }
}
```

The `run_probe` function uses log-normal jitter *without* backoff (probe mode is diagnostic).

### 4. Per-invocation sigma randomization

To prevent parametric fingerprinting of the log-normal distribution shape across multiple
invocations, `sigma` is multiplied by a random factor uniform in `[0.5, 1.5)` once per
process run. With default `sigma = 0.4`, the effective sigma varies from `0.2` to `0.6`
across runs, preventing a defender from fitting a single `logNormal(μ, σ²)` distribution
to collected timing samples across multiple engagements. This randomization is applied in
the CLI binary's `randomize_sigma()` before passing to both the `Orchestrator` and
`run_probe`.

### 5. Inter-protocol base delay increase

The current 500ms–5s jitter band is replaced with an 8-second base (matching NimPlant's
default `sleepTime`) before jitter and backoff are applied. With `sigma = 0.4`, the
first-attempt delay has a median of 8s and a log-normal spread (roughly `5.4s–11.9s` within
one standard deviation, with an unbounded but low-probability right tail) rather than a hard
cutoff band. This breaks both the short-burst correlation SIEMs use to cluster probe packets
into a single "recon event," and the flat-distribution signature a fixed percent band would
still leave behind.

## Consequences

- **Dependencies**: `ad-time` library crate gains `getrandom = "0.3"` for the CSPRNG jitter
  functions in `time_src.rs`. The binary crate (`skewrun`) does not directly depend on
  `getrandom` — all CSPRNG usage is in the library.
- **`Orchestrator::resolve()`** gains a two-tier `failures` counter: timeout and config
  errors reset it to 0 (environmental — no packet sent), non-timeout errors increment it.
  Config errors also skip the inter-source sleep entirely. Delay is computed before the
  counter changes, so the first non-timeout failure uses `3^0 = 1×`.
- **Delay cap**: `jittered_delay()` uses `saturating_mul` and clamps the final delay to
  `MAX_DELAY_MS` (30 minutes). `lognormal_jitter_ms()` guards the `exp()` factor: values
  exceeding 1e6 or non-finite return `u64::MAX`, which the caller's `saturating_mul` and
  `.min(MAX_DELAY_MS)` absorb safely. This prevents overflow-abort from the workspace
  `overflow-checks = true` panic-on-overflow setting, even under extreme sigma (e.g., 300).
- **Sigma validation**: the `--jitter-sigma` CLI flag rejects `NaN`, `Inf`, and negative
  values via a `value_parser`. `--jitter-base-ms` rejects zero via a `value_parser`.
  Valid sigma is `[0.0, ∞)` (zero disables jitter entirely).
- **Per-invocation sigma randomization**: `randomize_sigma()` multiplies sigma by a random
  factor in `[0.5, 1.5)` once per process run, preventing parametric fingerprinting across
  multiple engagements.
- **Operator-visible**: With default `sigma = 0.4`, effective sigma is `0.2–0.6`, and
  first-attempt median delay is ~8s (log-normal). With 5-method source list all failing,
  worst-case cumulative delay is capped at `30 min × 5 = 2.5h` by `MAX_DELAY_MS`.
  In practice, any single protocol succeeds within the first attempt, so total runtime
  increases from ~2s to ~8–12s per invocation.
- **`run_probe`** uses log-normal jitter (same sigma randomization, same `probe_jitter()`
  function) but without backoff. Both the `sigma > 0` and `sigma == 0` branches apply
  `MAX_DELAY_MS`.
- The backoff multiplier is a low-cost hardening measure carried over from long-running C2
  beaconing models; its benefit for skewrun's short-lived invocations is plausible but
  unmeasured.
- `--jitter-sigma` (default 0.4) and `--jitter-base-ms` (default 8000) CLI flags shipped
  with this ADR's implementation.
