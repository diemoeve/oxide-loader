# Memory Forensics for Oxide Loader Detection

This guide covers Volatility3 commands for detecting Oxide loader chain artifacts.

## Prerequisites

```bash
# Install Volatility3
pip install volatility3

# Get memory dump (Windows)
winpmem_mini_x64.exe memdump.raw

# Get memory dump (Linux)
sudo dd if=/dev/mem of=memdump.raw bs=1M
# Or use LiME
```

## Stage 1 Detection

Stage 1 allocates RWX memory and executes fetched payload.

### Find RWX Memory Regions

```bash
# Windows - VAD analysis for suspicious protections
vol -f memdump.raw windows.vadinfo | grep -E "PAGE_EXECUTE_READWRITE|EXECUTE_READWRITE"

# Find private executable memory (injection indicator)
vol -f memdump.raw windows.malfind
```

### Expected Artifacts

- Process with RWX private memory
- Small (~15KB) executable with network capability
- Magic bytes 0x4F584944 in memory

## Stage 2 Detection

Stage 2 performs anti-analysis checks.

### Process Analysis

```bash
# Check for suspicious API calls in memory
vol -f memdump.raw windows.dlllist --pid <PID>

# Look for anti-debug indicators
vol -f memdump.raw windows.callbacks
```

### Expected Artifacts

- CPUID calls in code
- Registry access to VM keys
- IsDebuggerPresent import

## Stage 3 Detection

Stage 3 injects into explorer.exe (Windows) or creates memfd (Linux).

### Windows - CreateRemoteThread Detection

```bash
# Find injected code in explorer.exe
vol -f memdump.raw windows.malfind --pid <explorer_pid>

# Check threads in explorer
vol -f memdump.raw windows.threads --pid <explorer_pid>

# VAD analysis for RWX in explorer
vol -f memdump.raw windows.vadinfo --pid <explorer_pid> | grep EXECUTE_READWRITE
```

### Linux - memfd Detection

```bash
# Check for anonymous mapped files
vol -f memdump.raw linux.maps | grep "memfd"

# Find processes with deleted/anonymous executables
vol -f memdump.raw linux.pslist

# Check /proc/PID/maps for anonymous executable regions
vol -f memdump.raw linux.proc_maps
```

### Expected Artifacts

- PE header in unbacked (private) memory
- Thread starting from non-module address
- VAD with PAGE_EXECUTE_READWRITE protection
- Process accessing explorer.exe with PROCESS_ALL_ACCESS

## Full Chain Analysis

### Step-by-step Memory Analysis

1. **Identify suspicious processes**
   ```bash
   vol -f memdump.raw windows.pstree
   vol -f memdump.raw windows.cmdline
   ```

2. **Check for network connections**
   ```bash
   vol -f memdump.raw windows.netscan | grep -E "8080|4444"
   ```

3. **Find injected code**
   ```bash
   vol -f memdump.raw windows.malfind --dump-dir ./extracted/
   ```

4. **Analyze extracted payloads**
   ```bash
   # Run YARA on extracted memory regions
   yara -r ../yara/*.yar ./extracted/
   ```

5. **Check process handles**
   ```bash
   vol -f memdump.raw windows.handles --pid <pid>
   ```

## YARA Integration

Run YARA rules against memory dump:

```bash
# Direct memory scan
vol -f memdump.raw yarascan.YaraScan --yara-file ../yara/stage3_injection.yar

# Scan extracted regions
yara -r ../yara/ ./extracted/
```

## Artifact Summary

| Stage | Memory Artifact | Detection Method |
|-------|----------------|------------------|
| 1 | RWX allocation, HTTP fetch | malfind, netscan |
| 2 | Anti-analysis strings | yarascan, dlllist |
| 3 | PE in unbacked memory | malfind, vadinfo |
| 3 | Remote thread in explorer | threads, handles |

## References

- Volatility3: https://github.com/volatilityfoundation/volatility3
- malfind plugin: Detects hidden/injected code
- vadinfo plugin: Virtual Address Descriptor analysis
