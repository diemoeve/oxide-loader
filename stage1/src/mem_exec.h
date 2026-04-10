/*
 * Memory Execution Header
 *
 * Detection artifact: RWX memory allocation
 * Memory forensics target: PE/ELF in unbacked memory
 */

#ifndef MEM_EXEC_H
#define MEM_EXEC_H

#include <stdint.h>
#include <stddef.h>

/*
 * Allocate RWX memory, copy code, and run.
 *
 * @param code     Shellcode/PE/ELF to run
 * @param len      Length of code
 * @return         0 on success (may not return), -1 on error
 */
int mem_run(const uint8_t *code, size_t len);

#endif /* MEM_EXEC_H */
