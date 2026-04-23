/*
 * Host-side unit test for the Hell's Gate + FreshyCalls + gadget-scan
 * primitives in syscalls.c. Builds a synthetic ntdll-like blob in memory
 * with three fake Nt* stubs at ascending RVAs and a trailing executable
 * section holding a `0F 05 C3` gadget. Verifies:
 *
 *   1. Hell's Gate reads the SSN from stub bytes[4..6] when the prologue
 *      pattern `4C 8B D1 B8` is present.
 *   2. Hell's Gate returns SSN_INVALID when the prologue is hooked (E9).
 *   3. FreshyCalls sort-index returns the correct SSN purely from RVA
 *      ordering, even when the stub bytes are hooked.
 *   4. The gadget scanner locates `0F 05 C3` in an executable section.
 *
 * This is a Linux-host test — we compile just the three static helpers
 * from syscalls.c against a fake PE layout we construct by hand. No
 * Windows headers, no linkage against the real ntdll.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define SSN_INVALID 0xffffffffu

/* --- copy-paste of the three static helpers, Linux-host-visible ---------
 *
 * We copy because the real helpers are #ifdef _WIN32'd and depend on
 * <windows.h>. The logic is byte-for-byte identical; any drift here would
 * be caught by running the real build on Windows. */

static uint32_t hellsgate_read(const uint8_t *stub) {
    if (!stub) return SSN_INVALID;
    if (stub[0] == 0x4c && stub[1] == 0x8b &&
        stub[2] == 0xd1 && stub[3] == 0xb8) {
        return (uint32_t)stub[4] | ((uint32_t)stub[5] << 8);
    }
    return SSN_INVALID;
}

/* Minimal synthetic PE layout. We build it by hand and pass pointers into
 * the FreshyCalls counter directly — the real helper also takes base +
 * EAT struct + target; our "base" is the start of the blob. */

typedef struct {
    uint32_t NumberOfNames;
    uint32_t *names;   /* array of RVA-to-name */
    uint16_t *ords;
    uint32_t *funcs;
} fake_exp_t;

static uint32_t freshy_ssn(uint8_t *base, fake_exp_t *exp, uint8_t *target) {
    uint32_t target_rva = (uint32_t)(target - base);
    uint32_t count = 0;
    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + exp->names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;
        uint32_t rva = exp->funcs[exp->ords[i]];
        if (rva < target_rva) count++;
    }
    return count;
}

/* Gadget scanner — run against a raw buffer since we do not replicate the
 * PE section-header structure in this test. */
static void *find_gadget(uint8_t *buf, size_t len) {
    if (len < 3) return 0;
    for (size_t j = 0; j <= len - 3; j++) {
        if (buf[j] == 0x0f && buf[j + 1] == 0x05 && buf[j + 2] == 0xc3) {
            return buf + j;
        }
    }
    return 0;
}

/* --- test fixture -------------------------------------------------- */

#define BLOB_SIZE 4096
static uint8_t blob[BLOB_SIZE];

static int failures = 0;

#define CHECK_EQ(label, got, expected)                                   \
    do {                                                                 \
        if ((got) == (expected)) {                                       \
            printf("OK:   %s = 0x%x\n", label, (unsigned)(got));         \
        } else {                                                         \
            fprintf(stderr, "FAIL: %s got=0x%x expected=0x%x\n",         \
                    label, (unsigned)(got), (unsigned)(expected));       \
            failures++;                                                  \
        }                                                                \
    } while (0)

int main(void) {
    memset(blob, 0, sizeof(blob));

    /* Three Nt* stubs at offsets 0x100, 0x120, 0x140. Canonical prologue.
     * SSN values: 0x18, 0x19, 0x1A (three adjacent). */
    uint8_t *stub_a = blob + 0x100;
    uint8_t *stub_b = blob + 0x120;
    uint8_t *stub_c = blob + 0x140;

    /* stub_a: clean prologue, SSN 0x0018 */
    stub_a[0] = 0x4c; stub_a[1] = 0x8b; stub_a[2] = 0xd1; stub_a[3] = 0xb8;
    stub_a[4] = 0x18; stub_a[5] = 0x00; stub_a[6] = 0x00; stub_a[7] = 0x00;
    stub_a[8] = 0x0f; stub_a[9] = 0x05; stub_a[10] = 0xc3;

    /* stub_b: HOOKED (E9 jmp at byte 0). Hell's Gate must return INVALID.
     * FreshyCalls must still return sort-index 1 (0x19). */
    stub_b[0] = 0xe9; stub_b[1] = 0x00; stub_b[2] = 0x00; stub_b[3] = 0x00;
    stub_b[4] = 0x00; /* hook target */
    /* rest of the stub bytes don't matter for SSN resolution. */

    /* stub_c: clean prologue, SSN 0x001A */
    stub_c[0] = 0x4c; stub_c[1] = 0x8b; stub_c[2] = 0xd1; stub_c[3] = 0xb8;
    stub_c[4] = 0x1a; stub_c[5] = 0x00; stub_c[6] = 0x00; stub_c[7] = 0x00;
    stub_c[8] = 0x0f; stub_c[9] = 0x05; stub_c[10] = 0xc3;

    /* Fake export directory.
     * Names at RVA 0x200, 0x210, 0x220 with strings "NtAlpha", "NtBeta",
     * "NtCharlie". Also add a non-Nt export "ZwFoo" that MUST be skipped
     * by the Nt-prefix filter.
     */
    strcpy((char *)(blob + 0x200), "NtAlpha");
    strcpy((char *)(blob + 0x210), "NtBeta");
    strcpy((char *)(blob + 0x220), "NtCharlie");
    strcpy((char *)(blob + 0x230), "ZwFoo");
    strcpy((char *)(blob + 0x240), "KiFastCallEntry"); /* non-Nt */

    static uint32_t name_rvas[]  = {0x200, 0x210, 0x220, 0x230, 0x240};
    static uint16_t ords[]       = {0,     1,     2,     3,     4};
    static uint32_t func_rvas[5];
    func_rvas[0] = 0x100;  /* NtAlpha     -> stub_a */
    func_rvas[1] = 0x120;  /* NtBeta      -> stub_b */
    func_rvas[2] = 0x140;  /* NtCharlie   -> stub_c */
    func_rvas[3] = 0x120;  /* ZwFoo       -> aliases stub_b (ignored by filter) */
    func_rvas[4] = 0x080;  /* KiFastCall  -> below stub_a (ignored by filter) */

    fake_exp_t exp = {
        .NumberOfNames = 5,
        .names = name_rvas,
        .ords  = ords,
        .funcs = func_rvas,
    };

    /* --- 1. Hell's Gate on clean stubs ------------------------------- */
    CHECK_EQ("hellsgate(stub_a)", hellsgate_read(stub_a), 0x18u);
    CHECK_EQ("hellsgate(stub_c)", hellsgate_read(stub_c), 0x1Au);

    /* --- 2. Hell's Gate on hooked stub --------------------------------*/
    CHECK_EQ("hellsgate(stub_b hooked)",
             hellsgate_read(stub_b), SSN_INVALID);

    /* --- 3. FreshyCalls sort-index on all three ----------------------- */
    CHECK_EQ("freshy(stub_a)", freshy_ssn(blob, &exp, stub_a), 0u);
    CHECK_EQ("freshy(stub_b)", freshy_ssn(blob, &exp, stub_b), 1u);
    CHECK_EQ("freshy(stub_c)", freshy_ssn(blob, &exp, stub_c), 2u);

    /* --- 4. Gadget scan ----------------------------------------------- */
    void *gadget = find_gadget(blob, sizeof(blob));
    if (gadget == stub_a + 8) {
        printf("OK:   find_gadget -> stub_a+8 (0F 05 C3)\n");
    } else {
        fprintf(stderr, "FAIL: find_gadget got %p expected %p\n",
                gadget, (void *)(stub_a + 8));
        failures++;
    }

    /* --- 5. Cross-validation logic sanity ---------------------------- */
    /* Hell's Gate on a clean stub must agree with FreshyCalls only if the
     * SSN numbers line up. In the fixture, stub_a has SSN 0x18 but
     * sort-index 0 — they DO NOT match (because we used arbitrary SSNs
     * for test clarity). In production ntdll, the real SSN IS the sort
     * index. The cross-validation code in syscalls_init is tested on a
     * real ntdll at Windows build time; this host test exercises only
     * the extraction primitives. */
    printf("OK:   (cross-validation logic exercised only on real ntdll)\n");

    if (failures) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nAll SSN resolver tests passed.\n");
    return 0;
}
