import time
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from Crypto.Cipher import AES as PyCryptoAES

# =============================================================================
# 1. VULNERABLE AES IMPLEMENTATION (Naive / Leaky Toy)
# =============================================================================

class VulnerableAES:
    """
    Naive / leaky toy implementation:

    - Simulates cache timing differences via _simulate_cache_latency(byte_val),
      which does different amounts of work depending on the input byte.
    - Not real AES; we only care about timing behaviour.
    """
    def __init__(self, key):
        self.key = key
        # Toy S-box table (AES-like values, repeated to make 256 entries)
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
            0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        ] * 8  # 32 * 8 = 256 entries

    def _simulate_cache_latency(self, byte_val: int) -> int:
        """
        Simulated leaky timing:

          - byte_val > 200  -> slow (cache miss style)
          - byte_val == 0   -> very slow (special case)
          - else            -> fast

        This creates a *strong* correlation between input and timing,
        like an exaggerated cache side-channel.
        """
        dummy = 0
        if byte_val > 200:
            # Slow path
            for x in range(100):
                dummy += x
        elif byte_val == 0:
            # Very slow path
            for x in range(150):
                dummy += x
        else:
            # Fast path
            for x in range(10):
                dummy += x
        return dummy

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Toy "encrypt": leak timing via _simulate_cache_latency and XOR with key.
        """
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes")

        output = bytearray(16)
        for i in range(16):
            val = plaintext[i]

            # Leaky timing: branches depend on byte value
            self._simulate_cache_latency(val)

            # Simple substitution / XOR with key (not real AES)
            output[i] = val ^ self.key[i]
        return bytes(output)


# =============================================================================
# 2. CONSTANT-TIME TOY IMPLEMENTATION (Algebraic S-box)
# =============================================================================

class CTToyAES:
    """
    Constant-time style toy using an algebraic S-box:

      - No large S-box table or secret-dependent indexing.
      - Just a fixed sequence of arithmetic/bit operations per byte.
      - Dummy work does the same number of iterations for any input.

    This models the idea of a "computed" constant-time S-box.
    """
    def __init__(self, key):
        self.key = key

    def _simulate_cache_latency_ct(self, byte_val: int) -> int:
        """
        Constant-time dummy work:

        - Always 150 iterations, no branches on byte_val.
        - byte_val only used inside arithmetic, not for control flow.
        """
        dummy = 0
        for x in range(150):
            dummy += x ^ byte_val
        return dummy

    def _algebraic_sbox(self, x: int) -> int:
        """
        Toy algebraic S-box (NOT the real AES S-box, but:

        - Same work for every input (no branches),
        - Only uses arithmetic and bit operations.

        You can tweak the formula; the important thing is that
        it does a fixed sequence of operations independent of x.
        """
        x &= 0xFF
        y = (x * 17) & 0xFF
        # rotate-left 1
        r1 = ((x << 1) | (x >> 7)) & 0xFF
        # rotate-left 2
        r2 = ((x << 2) | (x >> 6)) & 0xFF
        y ^= r1
        y ^= r2
        y ^= 0x5A
        return y

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Toy "encrypt" using:

          - constant-time dummy work,
          - algebraic S-box,
          - XOR with key.

        Still not real AES, but structurally constant-time (no branches
        or table lookups based on secret data).
        """
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes")

        output = bytearray(16)
        for i in range(16):
            val = plaintext[i]

            # Constant-time dummy work (fixed iterations)
            self._simulate_cache_latency_ct(val)

            # Algebraic S-box (fixed sequence of operations)
            sb = self._algebraic_sbox(val)

            # Mix with key (toy)
            output[i] = sb ^ self.key[i]
        return bytes(output)


# =============================================================================
# 3. SAFE AES IMPLEMENTATION (PyCryptodome, hardware AES if available)
# =============================================================================

class SafeAES:
    """
    Wrapper for PyCryptodome AES (MODE_ECB).
    PyCryptodome uses constant-time code, and on x86 it typically uses AES-NI
    if the CPU and build support it.
    """
    def __init__(self, key):
        self.cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_ECB)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher.encrypt(plaintext)


# =============================================================================
# 4. EXPERIMENTAL HARNESS
# =============================================================================

def measure_time(encrypt_func, plaintext: bytes, num_runs: int = 100) -> float:
    """
    Measure average execution time of encrypt_func(plaintext) in nanoseconds,
    similar to Python's time.perf_counter_ns().
    """
    timer = time.perf_counter_ns

    # Warm-up
    encrypt_func(plaintext)

    start = timer()
    for _ in range(num_runs):
        encrypt_func(plaintext)
    end = timer()

    return (end - start) / num_runs


def generate_dataset():
    print("--- Starting AES side-channel data collection (3 implementations) ---")

    # Fixed random key
    KEY = os.urandom(16)

    vuln_aes = VulnerableAES(KEY)
    ct_toy   = CTToyAES(KEY)
    safe_aes = SafeAES(KEY)

    # Parameters – tweak if you want more precision
    SAMPLES_PER_BYTE   = 50      # number of samples per input byte value
    LOOPS_PER_MEASURE  = 500     # encryptions inside 1 timing measurement

    data_records = []

    print(f"Collecting data for 256 byte values...")
    for byte_val in range(256):
        if byte_val % 50 == 0:
            print(f"  progress: {byte_val}/255")

        for sample_id in range(SAMPLES_PER_BYTE):
            # Plaintext: pt[0] = controlled byte, pt[1..15] = 1
            pt = bytearray([1] * 16)
            pt[0] = byte_val
            plaintext = bytes(pt)

            # 1) Vulnerable (Naive)
            t_vuln = measure_time(vuln_aes.encrypt, plaintext, LOOPS_PER_MEASURE)
            data_records.append({
                "implementation": "Vulnerable (Naive)",
                "byte_value": byte_val,
                "time_ns": t_vuln,
                "sample_id": sample_id,
            })

            # 2) Safe Toy (CT algebraic S-Box)
            t_ct_toy = measure_time(ct_toy.encrypt, plaintext, LOOPS_PER_MEASURE)
            data_records.append({
                "implementation": "Safe Toy (CT SBox)",
                "byte_value": byte_val,
                "time_ns": t_ct_toy,
                "sample_id": sample_id,
            })

            # 3) Safe (PyCryptodome)
            t_safe = measure_time(safe_aes.encrypt, plaintext, LOOPS_PER_MEASURE)
            data_records.append({
                "implementation": "Safe (PyCryptodome)",
                "byte_value": byte_val,
                "time_ns": t_safe,
                "sample_id": sample_id,
            })

    print("Data collection complete.")

    df = pd.DataFrame(data_records)
    csv_filename = "aes_timing_dataset_AZ.csv"
    df.to_csv(csv_filename, index=False)
    print(f"Dataset saved to: {csv_filename}")

    return df


# =============================================================================
# 5. BASIC ANALYSIS & PLOT (for a quick look)
# =============================================================================

def analyze_and_plot(df: pd.DataFrame):
    print("Generating basic comparison plot (Vulnerable vs CT Toy vs PyCryptodome)...")
    sns.set_theme(style="whitegrid")

    summary = df.groupby(["implementation", "byte_value"])["time_ns"].mean().reset_index()

    plt.figure(figsize=(12, 6))
    sns.lineplot(
        data=summary,
        x="byte_value",
        y="time_ns",
        hue="implementation",
        estimator=None,
    )
    plt.title("Mean time vs first plaintext byte\nVulnerable vs CT Toy vs PyCryptodome")
    plt.xlabel("byte_value (0–255)")
    plt.ylabel("time_ns (average per call)")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("aes_toy_ct_pycrypto_mean_time_vs_byte.png", dpi=150)
    print("Saved aes_toy_ct_pycrypto_mean_time_vs_byte.png")
    plt.show()


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # Regenerate dataset if missing; otherwise reuse it
    if not os.path.exists("aes_timing_dataset_AZ.csv"):
        dataset = generate_dataset()
    else:
        print("Loading existing dataset from CSV...")
        dataset = pd.read_csv("aes_timing_dataset_AZ.csv")

    analyze_and_plot(dataset)
