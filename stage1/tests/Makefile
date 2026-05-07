# Linux host tests for stage1 primitives.
# Fast feedback loop — catches hash drift and XS roundtrip regressions
# before the Windows cross-build.

CC := gcc
CFLAGS := -O2 -Wall -Wextra -Werror -I../src -std=c11

.PHONY: all clean run

all: test_hash test_xs test_ssn

test_hash: test_hash.c ../src/hash.h
	$(CC) $(CFLAGS) -o $@ test_hash.c

test_xs: test_xs.c ../src/xor_string.h ../src/xor_string.c
	$(CC) $(CFLAGS) -o $@ test_xs.c ../src/xor_string.c

test_ssn: test_ssn.c
	$(CC) $(CFLAGS) -o $@ test_ssn.c

run: all
	@echo "=== test_hash ==="
	@./test_hash
	@echo
	@echo "=== test_xs ==="
	@./test_xs
	@echo
	@echo "=== test_ssn ==="
	@./test_ssn

clean:
	rm -f test_hash test_xs test_ssn
