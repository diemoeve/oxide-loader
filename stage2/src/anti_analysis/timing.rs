//! Timing-based Detection Module
//!
//! Techniques:
//! - Sleep acceleration detection (sandboxes skip/shorten sleeps)
//! - RDTSC timing check (detect fast-forwarding)
//!
//! Detection artifacts:
//! - ETW: Timing anomalies

use super::AnalysisEnvironment;
use std::time::{Duration, Instant};

/// Expected minimum sleep duration (allowing for ~20% variance)
const SLEEP_DURATION_MS: u64 = 1000;
const MIN_EXPECTED_MS: u64 = 800;  // 80% of requested

/// RDTSC threshold for 100ms (approximate cycles)
/// Modern CPUs: ~3GHz = 3*10^9 cycles/sec = 3*10^8 cycles/100ms
const RDTSC_MIN_CYCLES_100MS: u64 = 100_000_000;  // Conservative: 1GHz CPU

/// Run timing checks.
pub fn check() -> Result<(), AnalysisEnvironment> {
    // Sleep acceleration check
    if check_sleep_acceleration() {
        return Err(AnalysisEnvironment::TimingAnomaly);
    }

    // RDTSC check (x86/x64 only)
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if check_rdtsc_anomaly() {
        return Err(AnalysisEnvironment::TimingAnomaly);
    }

    Ok(())
}

/// Check if sleep is being accelerated.
fn check_sleep_acceleration() -> bool {
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(SLEEP_DURATION_MS));
    let elapsed = start.elapsed();

    // If elapsed time is significantly less than requested, sleep was accelerated
    elapsed.as_millis() < MIN_EXPECTED_MS as u128
}

/// Check RDTSC timing for anomalies.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn check_rdtsc_anomaly() -> bool {
    let start = rdtsc();

    // Busy loop for ~100ms worth of work
    let loop_start = Instant::now();
    while loop_start.elapsed() < Duration::from_millis(100) {
        // Busy wait
        std::hint::spin_loop();
    }

    let end = rdtsc();
    let cycles = end.saturating_sub(start);

    // If cycles are suspiciously low, we might be in a VM with TSC interception
    cycles < RDTSC_MIN_CYCLES_100MS
}

/// Read Time Stamp Counter.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        std::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
        );
        ((hi as u64) << 32) | (lo as u64)
    }

    #[cfg(target_arch = "x86")]
    unsafe {
        let lo: u32;
        let hi: u32;
        std::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}
