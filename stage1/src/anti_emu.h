/*
 * S40 — anti-emulation timing probe.
 *
 * Three-guard execution-environment check. Runs early in stage1_entry,
 * after decoys_run() and before resolve_apis(). On real hardware all
 * three guards complete in ~9.5 s and the loader continues normally.
 * On environments that fake Sleep or skip CPU loops, the probe self-
 * terminates the process via ExitProcess(0) before any network or
 * syscall surface is touched.
 *
 * Guards:
 *   1. QPC bracket around Sleep(8000) — divergence under 3.2 s fails
 *      the floor (Sleep-skip emulators trip; real Sleep returns no
 *      earlier than requested).
 *   2. Bounded QPC loop (1500 ms wall-clock) with iter counter — under
 *      1M iterations fails (iteration-bounded emulators trip; modern
 *      x86_64 sustains 100M+ iter / 1.5 s).
 *   3. CPUID leaf 1 ECX bit 31 (HV-present) — informational only,
 *      stored in a volatile sink. Never gated, because the lab is KVM
 *      (HV-bit always set) and most enterprise endpoints in 2026 are
 *      HV-enlightened (Hyper-V / VBS).
 *
 * Module is self-contained — it does its own minimal PEB walk for the
 * four kernel32 exports it needs (Sleep, ExitProcess, QPC, QPF) so it
 * can run before resolve_apis() populates g_api. None of the four
 * appear in the IAT; the S39 12-entry common-utility silhouette is
 * preserved.
 *
 * Detection pairing:
 *   detection/yara/stage1_qpc_sleep_divergence_check.yar (T1497.003)
 *   detection/sigma/stage1_long_sleep_pre_network.yml    (T1497.003)
 *
 * Failure mode: PEB walk failure (all four exports must resolve) is
 * treated as a fail-closed signal — the binary cannot trust its own
 * import resolution at that point and exits via the kernel32 IAT
 * decoy entries are not present for ExitProcess, so the only fail
 * action available without resolved exports is an infinite loop. The
 * implementation chooses: if the PEB walk fails, the loader falls
 * through to the existing flow, which itself fails resolve_apis() and
 * exits cleanly. This preserves robustness on hosts where PEB layout
 * is unexpected.
 */

#ifndef ANTI_EMU_H
#define ANTI_EMU_H

#ifdef _WIN32

/*
 * Run the three timing guards. On guard fail, terminates the process
 * via ExitProcess(0). On pass, returns normally and the caller
 * continues to resolve_apis().
 */
void anti_emu_run(void);

#endif /* _WIN32 */
#endif /* ANTI_EMU_H */
