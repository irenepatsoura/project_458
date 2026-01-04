// bearssl_aes_timing_simple.c
//
// Timing comparison of BearSSL AES-big, AES-small (both table-based, not CT)
// vs AES-ct (constant-time) using the SAME CSV format as your Python script:
//
//   implementation,byte_value,time_ns,sample_id
//
// NOTE: "time_ns" actually contains CPU cycles here, not true nanoseconds,
// but you can still treat it as "time units" for plotting and comparison.
//
// Compile on Linux / WSL with BearSSL dev installed:
//   gcc -O2 -march=native -Wall bearssl_aes_timing_simple.c -o bearssl_aes_timing_simple -lbearssl
//
// Run:
//   ./bearssl_aes_timing_simple
//
// This produces bearssl_aes_timing.csv which you can analyze in Python.

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#endif

#include <x86intrin.h>   // __rdtsc, cpuid
#include <bearssl.h>     // BearSSL block cipher API

// ---------------- CONFIG ----------------

#define BLOCK_SIZE          16
#define NUM_PLAIN_VALUES    256     // pt[0] from 0..255

// MORE SAMPLES to reduce noise:
#define SAMPLES_PER_BYTE    200     // was 50
#define LOOPS_PER_MEASURE   2000    // was 500

// ---------------- CPU PINNING (Linux only, optional) ----------------

static void pin_to_cpu0(void) {
#ifdef __linux__
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
    }
#else
    (void)0; // no-op on non-Linux
#endif
}

// ---------------- TIMING HELPERS ----------------

static inline uint64_t rdtsc_start(void) {
    // serialize before reading TSC
    __asm__ volatile ("cpuid" : : "a"(0) : "%rbx", "%rcx", "%rdx");
    return __rdtsc();
}

static inline uint64_t rdtsc_end(void) {
    return __rdtsc();
}

// ---------------- BEARSSL AES WRAPPERS ----------------
//
// We use:
//   - AES-big  CBC enc as a "leaky" implementation (large T-tables, not CT)
//   - AES-small CBC enc as another non-CT implementation
//   - AES-ct   CBC enc as the constant-time implementation
//
// All are used in ECB-style by encrypting a single block with IV = 0:
//
//    ECB(pt) ≈ CBC_encrypt(key, IV=0, pt, len=16)

static br_aes_big_cbcenc_keys   g_big_ctx;
static br_aes_small_cbcenc_keys g_small_ctx;
static br_aes_ct_cbcenc_keys    g_ct_ctx;

// ECB-style encrypt using AES-big CBC enc (IV=0, one block)
static void aes_big_ecb(const uint8_t in[BLOCK_SIZE],
                        uint8_t out[BLOCK_SIZE])
{
    uint8_t tmp[BLOCK_SIZE];
    uint8_t iv[BLOCK_SIZE];

    memcpy(tmp, in, BLOCK_SIZE);
    memset(iv, 0, BLOCK_SIZE);

    br_aes_big_cbcenc_run(&g_big_ctx, iv, tmp, BLOCK_SIZE);
    memcpy(out, tmp, BLOCK_SIZE);
}

// ECB-style encrypt using AES-small CBC enc
static void aes_small_ecb(const uint8_t in[BLOCK_SIZE],
                          uint8_t out[BLOCK_SIZE])
{
    uint8_t tmp[BLOCK_SIZE];
    uint8_t iv[BLOCK_SIZE];

    memcpy(tmp, in, BLOCK_SIZE);
    memset(iv, 0, BLOCK_SIZE);

    br_aes_small_cbcenc_run(&g_small_ctx, iv, tmp, BLOCK_SIZE);
    memcpy(out, tmp, BLOCK_SIZE);
}

// ECB-style encrypt using AES-ct CBC enc
static void aes_ct_ecb(const uint8_t in[BLOCK_SIZE],
                       uint8_t out[BLOCK_SIZE])
{
    uint8_t tmp[BLOCK_SIZE];
    uint8_t iv[BLOCK_SIZE];

    memcpy(tmp, in, BLOCK_SIZE);
    memset(iv, 0, BLOCK_SIZE);

    br_aes_ct_cbcenc_run(&g_ct_ctx, iv, tmp, BLOCK_SIZE);
    memcpy(out, tmp, BLOCK_SIZE);
}

// ---------------- MEASUREMENT HARNESS ----------------

typedef void (*aes_block_enc_fn)(const uint8_t in[BLOCK_SIZE],
                                 uint8_t out[BLOCK_SIZE]);

// Measure average cycles for one plaintext, for a given encrypt function
static double measure_cycles(aes_block_enc_fn f,
                             const uint8_t pt[BLOCK_SIZE],
                             int loops)
{
    uint8_t ct[BLOCK_SIZE];

    // Warm-up
    f(pt, ct);

    uint64_t start = rdtsc_start();
    for (int i = 0; i < loops; i++) {
        f(pt, ct);
    }
    uint64_t end = rdtsc_end();

    uint64_t total = end - start;
    return (double)total / (double)loops;
}

// ---------------- MAIN ----------------

int main(void) {
    pin_to_cpu0();

    // Fixed secret key (for reproducibility)
    uint8_t key[BLOCK_SIZE] = {
        0x3C, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    // Init BearSSL AES-big, AES-small and AES-ct CBC enc contexts
    br_aes_big_cbcenc_init(&g_big_ctx,   key, sizeof key);
    br_aes_small_cbcenc_init(&g_small_ctx, key, sizeof key);
    br_aes_ct_cbcenc_init(&g_ct_ctx,     key, sizeof key);

    uint8_t pt[BLOCK_SIZE];

    // Open CSV (same-style header as your Python code)
    FILE *fp = fopen("bearssl_aes_timing.csv", "w");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    // NOTE: column name is "time_ns" to match your Python, but values are cycles
    fprintf(fp, "implementation,byte_value,time_ns,sample_id\n");

    printf("Collecting data for %d byte values, %d samples each...\n",
           NUM_PLAIN_VALUES, SAMPLES_PER_BYTE);

    for (int byte = 0; byte < NUM_PLAIN_VALUES; byte++) {
        if (byte % 16 == 0) {
            printf("  progress: %d/%d\n", byte, NUM_PLAIN_VALUES - 1);
        }

        for (int s = 0; s < SAMPLES_PER_BYTE; s++) {
            // Plaintext: pt[0] controlled, pt[1..15] = 0x01
            pt[0] = (uint8_t)byte;
            for (int i = 1; i < BLOCK_SIZE; i++) {
                pt[i] = 0x01;
            }

            // 1) AES-big (leaky, table-based)
            double cyc_big = measure_cycles(aes_big_ecb, pt, LOOPS_PER_MEASURE);
            fprintf(fp, "AES_big,%d,%.2f,%d\n", byte, cyc_big, s);

            // 2) AES-small (another non-CT implementation)
            double cyc_small = measure_cycles(aes_small_ecb, pt, LOOPS_PER_MEASURE);
            fprintf(fp, "AES_small,%d,%.2f,%d\n", byte, cyc_small, s);

            // 3) AES-ct (constant-time)
            double cyc_ct = measure_cycles(aes_ct_ecb, pt, LOOPS_PER_MEASURE);
            fprintf(fp, "AES_ct,%d,%.2f,%d\n", byte, cyc_ct, s);
        }
    }

    fclose(fp);
    printf("Done. Results written to bearssl_aes_timing.csv\n");

    return 0;
}
