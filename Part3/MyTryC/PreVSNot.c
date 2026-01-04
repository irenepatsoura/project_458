// sbox_timing.c
//
// Compare timing of:
//   - Precomputed S-box (table lookup + Python-style leaky dummy)
//   - Algebraic S-box (computed on the fly, fixed operations)
//
// Output CSV format:
//
//   implementation,byte_value,time_ns,sample_id
//
// Here time_ns is truly "nanoseconds" per encrypt (average over LOOPS_PER_MEASURE),
// similar to Python's time.perf_counter_ns().
//
// Compile on Linux / WSL (GCC):
//   gcc -O2 -march=native -Wall sbox_timing.c -o sbox_timing
//
// On Windows with MinGW:
//   gcc -O2 -march=native -Wall sbox_timing.c -o sbox_timing.exe
//
// Run:
//   ./sbox_timing
//
// This creates: sbox_precomputed_vs_algebraic.csv

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#elif defined(__linux__)
#include <sched.h>
#include <unistd.h>
#endif

// ---------------- CONFIG ----------------

#define BLOCK_SIZE          16
#define NUM_PLAIN_VALUES    256     // pt[0] from 0..255

// Increase for less noise (but slower)
#define SAMPLES_PER_BYTE    100
#define LOOPS_PER_MEASURE   1000

// ---------------- CPU PINNING (Linux + Windows) ----------------

static void pin_to_cpu0(void) {
#ifdef _WIN32
    HANDLE hThread = GetCurrentThread();
    DWORD_PTR mask = 1;            // bit 0 -> CPU 0
    DWORD_PTR result = SetThreadAffinityMask(hThread, mask);
    if (result == 0) {
        fprintf(stderr, "SetThreadAffinityMask failed\n");
    }
#elif defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
    }
#else
    (void)0; // no-op on other systems
#endif
}

// ---------------- HIGH-RES TIMER IN NANOSECONDS ----------------
//
// get_time_ns() returns a double nanoseconds value, similar to
// Python's time.perf_counter_ns() (but as double).

static double get_time_ns(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq;
    static int freq_init = 0;
    LARGE_INTEGER counter;

    if (!freq_init) {
        if (!QueryPerformanceFrequency(&freq)) {
            // Fallback: just use GetTickCount, very coarse, but shouldn't happen
            return (double)GetTickCount() * 1e6;
        }
        freq_init = 1;
    }

    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1e9 / (double)freq.QuadPart;

#elif defined(__linux__)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
#else
    // Very generic fallback (low resolution)
    return (double)clock() * (1e9 / (double)CLOCKS_PER_SEC);
#endif
}

// ---------------- TOY S-BOXES ----------------

// Precomputed S-box table (toy, repeated pattern)
static const uint8_t PRECOMP_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
};

// Simple 8-bit rotate-left
static inline uint8_t rotl8(uint8_t x, unsigned int n) {
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

// "Algebraic" S-box: compute on the fly with fixed operations
// (NOT the real AES S-box, but constant work for all inputs).
static uint8_t algebraic_sbox(uint8_t x) {
    uint8_t y = (uint8_t)(x * 17u);
    y ^= rotl8(x, 1);
    y ^= rotl8(x, 2);
    y ^= 0x5Au;
    return y;
}

// ---------------- LEAKY DUMMY WORK (Python-style) ----------------
//
// Mirrors your Python _simulate_cache_latency(byte_val):
//
// if byte_val > 200:   # cold, slower    -> 100 iters
// elif byte_val == 0:  # special case    -> 150 iters
// else:                # hot, fast       -> 10 iters
//
static void leaky_dummy(uint8_t idx) {
    volatile int dummy = 0;

    if (idx > 200) {
        // Simulated cache miss / slow path
        for (int k = 0; k < 100; k++) {
            dummy += k;
        }
    } else if (idx == 0) {
        // Special case: even slower
        for (int k = 0; k < 150; k++) {
            dummy += k;
        }
    } else {
        // Fast path
        for (int k = 0; k < 10; k++) {
            dummy += k;
        }
    }
}

// ---------------- TOY "ENCRYPT" FUNCTIONS ----------------

// Precomputed S-box (table lookup + Python-style leaky dummy)
static void encrypt_precomputed(const uint8_t key[BLOCK_SIZE],
                                const uint8_t pt[BLOCK_SIZE],
                                uint8_t ct[BLOCK_SIZE])
{
    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t idx = (uint8_t)(pt[i] ^ key[i]);

        // Secret-dependent extra work, like your Python toy:
        // leaky_dummy(idx);

        ct[i] = PRECOMP_SBOX[idx];   // table lookup
    }
}

// Algebraic S-box (computed on the fly, same work per input)
static void encrypt_algebraic(const uint8_t key[BLOCK_SIZE],
                              const uint8_t pt[BLOCK_SIZE],
                              uint8_t ct[BLOCK_SIZE])
{
    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t idx = (uint8_t)(pt[i] ^ key[i]);
        uint8_t sb  = algebraic_sbox(idx);     // same sequence of ops for all idx
        ct[i] = sb;
    }
}

// ---------------- MEASUREMENT HARNESS ----------------

typedef void (*encrypt_func_t)(const uint8_t key[BLOCK_SIZE],
                               const uint8_t pt[BLOCK_SIZE],
                               uint8_t ct[BLOCK_SIZE]);

// Measure average nanoseconds per call for one plaintext
static double measure_ns(encrypt_func_t f,
                         const uint8_t key[BLOCK_SIZE],
                         const uint8_t pt[BLOCK_SIZE],
                         int loops)
{
    uint8_t ct[BLOCK_SIZE];

    // Warm-up
    f(key, pt, ct);

    double start = get_time_ns();
    for (int i = 0; i < loops; i++) {
        f(key, pt, ct);
    }
    double end = get_time_ns();

    double total = end - start;             // nanoseconds for all loops
    return total / (double)loops;           // avg ns per encrypt()
}

// ---------------- MAIN ----------------

int main(void) {
    // pin_to_cpu0();

    // Fixed secret key (for reproducibility)
    uint8_t key[BLOCK_SIZE] = {
        0x3C, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    uint8_t pt[BLOCK_SIZE];

    FILE *fp = fopen("sbox_precomputed_vs_algebraic_P3.csv", "w");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    // Same header style as your Python script
    fprintf(fp, "implementation,byte_value,time_ns,sample_id\n");

    printf("Collecting data for %d byte values, %d samples each...\n",
           NUM_PLAIN_VALUES, SAMPLES_PER_BYTE);

    for (int byte = 0; byte < NUM_PLAIN_VALUES; byte++) {
        if (byte % 16 == 0) {
            printf("  progress: %d/%d\n", byte, NUM_PLAIN_VALUES - 1);
        }

        for (int s = 0; s < SAMPLES_PER_BYTE; s++) {
            // Plaintext: pt[0] = controlled byte, pt[1..15] = 0x01
            pt[0] = (uint8_t)byte;
            for (int i = 1; i < BLOCK_SIZE; i++) {
                pt[i] = 0x01;
            }

            // 1) Precomputed S-box (with leaky dummy)
            double ns_pre = measure_ns(encrypt_precomputed, key, pt, LOOPS_PER_MEASURE);
            fprintf(fp, "Precomputed_SBox,%d,%.2f,%d\n", byte, ns_pre, s);

            // 2) Algebraic S-box (CT-style)
            double ns_alg = measure_ns(encrypt_algebraic, key, pt, LOOPS_PER_MEASURE);
            fprintf(fp, "Algebraic_SBox,%d,%.2f,%d\n", byte, ns_alg, s);
        }
    }

    fclose(fp);
    printf("Done. Results written to sbox_precomputed_vs_algebraic.csv\n");

    return 0;
}
