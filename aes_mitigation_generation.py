import time
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from aes_implementations import VulnerableAES, SafeAES, CTToyAES, measure_time

# =============================================================================
# 1. DATA GENERATION
# =============================================================================

def generate_dataset():
    print("--- Starting AES side-channel data collection (3 implementations) ---")

    # Fixed random key
    # Use a NULL KEY so that Plaintext == State (before S-Box).
    # This ensures our simple analysis (which looks at Plaintext byte values)
    # remains valid even though the leak is technically on (Plaintext ^ Key).
    KEY = bytes([0] * 16)

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
# 2. BASIC ANALYSIS & PLOT (for a quick look)
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
