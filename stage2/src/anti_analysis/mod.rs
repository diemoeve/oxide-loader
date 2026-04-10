//! Anti-analysis module
//!
//! Implements documented anti-analysis techniques for detection artifact generation.
//! Each technique produces specific detection artifacts (ETW, Sysmon, registry access).
//!
//! Detection targets:
//! - Sigma: stage2_vm_check.yml, stage2_debug_check.yml, stage2_sandbox.yml
//! - YARA: stage2_antivm.yar, stage2_antidebug.yar

pub mod vm_detect;
pub mod debugger;
pub mod sandbox;
pub mod timing;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalysisEnvironment {
    #[error("VM detected: {0}")]
    VirtualMachine(String),
    #[error("Debugger detected: {0}")]
    Debugger(String),
    #[error("Sandbox detected: {0}")]
    Sandbox(String),
    #[error("Timing anomaly detected")]
    TimingAnomaly,
}

/// Run all anti-analysis checks.
/// Returns Ok(()) if environment appears clean, Err with detection reason otherwise.
pub fn check_environment() -> Result<(), AnalysisEnvironment> {
    // Check for debugger first (fastest)
    debugger::check()?;

    // Check timing (sleep acceleration)
    timing::check()?;

    // Check for VM
    vm_detect::check()?;

    // Check for sandbox
    sandbox::check()?;

    Ok(())
}
