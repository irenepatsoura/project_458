import os
import itertools

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy import stats

sns.set_theme(style="whitegrid")


# ============================================================
# Helper: generic variance barplot
# ============================================================

def plot_variance_bar(variance, title, filename):
    plt.figure(figsize=(6, 5))
    plt.title(title)

    impls = variance.index.tolist()
    vals = variance.values

    bars = plt.bar(impls, vals)
    plt.yscale("log")
    for bar in bars:
        yval = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 3,
            yval,
            f"{yval:.6e}",
            va="bottom",
            ha="center",
        )

    plt.ylabel(r"Variance (ns$^2$)")
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    print(f"Variance plot saved as {filename}")
    plt.close()


# ============================================================
# 1. AES DATASET ANALYSIS (toy vulnerable, safe toy, PyCryptodome)
# ============================================================

def analyze_aes_dataset(csv_path="aes_timing_dataset.csv"):
    if not os.path.exists(csv_path):
        print(f"[!] {csv_path} not found.")
        return

    print(f"\n=== AES dataset analysis: {csv_path} ===\n")
    data = pd.read_csv(csv_path)

    # ------------------------------------------------------------------
    # Mean time per input byte per implementation
    # ------------------------------------------------------------------
    data_analysis = (
        data.groupby(["implementation", "byte_value"])["time_ns"]
        .mean()
        .unstack(level=0)
    )

    print("\n---- Mean time for each input (first 20 rows) ----\n")
    print(data_analysis.iloc[0:20])

    # ------------------------------------------------------------------
    # Variance per implementation
    # ------------------------------------------------------------------
    variance = data.groupby("implementation")["time_ns"].var()
    print("\n---- Variance Results ----\n")
    print(variance)

    plot_variance_bar(
        variance,
        title="AES: Variance per implementation",
        filename="aes_variance_comparison.png",
    )

    # ------------------------------------------------------------------
    # Pairwise Welch's t-tests between implementations
    # ------------------------------------------------------------------
    impls = data["implementation"].unique().tolist()
    print("\n------ Pairwise Welch's t-tests (AES) ------\n")
    for a, b in itertools.combinations(impls, 2):
        a_vals = data[data["implementation"] == a]["time_ns"]
        b_vals = data[data["implementation"] == b]["time_ns"]
        t_stat, p_val = stats.ttest_ind(a_vals, b_vals, equal_var=False)
        print(f"{a}  vs  {b}")
        print(f"  T-statistic: {t_stat:.4f}")
        print(f"  P-value    : {p_val:.10e}\n")

    # ------------------------------------------------------------------
    # Correlation between input byte and time, per implementation
    # ------------------------------------------------------------------
    print("\n------ Correlation (byte_value vs time_ns) ------\n")
    for impl in impls:
        subset = data[data["implementation"] == impl]
        correl = subset["byte_value"].corr(subset["time_ns"])
        print(f"{impl}: correlation = {correl:.4f}")
    print("\n")

    # ------------------------------------------------------------------
    # KDE of timing distributions
    # ------------------------------------------------------------------
    plt.figure(figsize=(10, 6))
    sns.kdeplot(
        data=data,
        x="time_ns",
        hue="implementation",
        common_norm=False,
        fill=True,
    )
    plt.title("AES: Timing Distribution per Implementation")
    plt.xlabel("Time (ns)")
    plt.ylabel("Density")
    plt.grid(axis="x", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("aes_timing_distribution.png", dpi=150)
    print("KDE plot saved as aes_timing_distribution.png")
    plt.close()

    # ------------------------------------------------------------------
    # Mean time vs byte_value (leak pattern)
    # ------------------------------------------------------------------
    plt.figure(figsize=(12, 6))
    sns.lineplot(
        data=data,
        x="byte_value",
        y="time_ns",
        hue="implementation",
        estimator="mean",
        errorbar=None,
    )
    plt.title("AES: Mean Execution Time vs Input Byte Value")
    plt.xlabel("Byte Value (0–255)")
    plt.ylabel("Time (ns)")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("aes_mean_time_vs_byte.png", dpi=150)
    print("Plot saved as aes_mean_time_vs_byte.png")
    plt.close()

    # ------------------------------------------------------------------
    # Detailed leak analysis: focus on the "vulnerable" toy implementation
    # ------------------------------------------------------------------
    # Try to detect a leaky toy impl name
    leaky_candidates = [
        name
        for name in impls
        if "Vulnerable" in name or "Leaky" in name or "Naive" in name
    ]
    leaky_name = leaky_candidates[0] if leaky_candidates else impls[0]
    print(f"\n------ Detailed Leak Analysis (AES, {leaky_name}) ------\n")

    vuln_data = data[data["implementation"] == leaky_name]

    group_low = vuln_data[
        (vuln_data["byte_value"] <= 200) & (vuln_data["byte_value"] > 0)
    ]["time_ns"]
    group_high = vuln_data[vuln_data["byte_value"] > 200]["time_ns"]
    group_zero = vuln_data[vuln_data["byte_value"] == 0]["time_ns"]

    print(f"Vulnerable Implementation: {leaky_name}")
    print(f"Mean time (0 < Byte <= 200): {group_low.mean():.2f} ns")
    print(f"Mean time (Byte > 200)     : {group_high.mean():.2f} ns")
    print(f"Difference (High - Low)    : {group_high.mean() - group_low.mean():.2f} ns")

    # T-test Low vs High
    t_stat_groups, p_val_groups = stats.ttest_ind(
        group_low, group_high, equal_var=False
    )
    print(f"T-statistic (Low vs High): {t_stat_groups:.4f}")
    print(f"P-value (Low vs High)   : {p_val_groups:.10e}")

    # Zero byte special case
    print("\nZero Byte Analysis:")
    print(f"Mean time (Byte == 0): {group_zero.mean():.2f} ns")
    print(
        f"Difference vs Low group: {group_zero.mean() - group_low.mean():.2f} ns"
    )

    # Boxplot by groups (Zero / Low / High)
    plt.figure(figsize=(8, 6))
    plot_data = vuln_data.copy()
    plot_data["Group"] = pd.cut(
        plot_data["byte_value"],
        bins=[-1, 0, 200, 256],
        labels=["Zero", "Low", "High"],
    )
    sns.boxplot(data=plot_data, x="Group", y="time_ns")
    plt.title(f"AES: Distribution of Execution Time by Byte Group ({leaky_name})")
    plt.ylabel("Time (ns)")
    plt.tight_layout()
    plt.savefig("aes_group_distribution.png", dpi=150)
    print("Plot saved as aes_group_distribution.png")
    plt.close()

    print("\n[Done] AES dataset analysis.\n")


# ============================================================
# 2. S-BOX PRECOMPUTED vs ALGEBRAIC ANALYSIS (C toy)
# ============================================================

def analyze_sbox_dataset(csv_path="sbox_precomputed_vs_algebraic.csv"):
    if not os.path.exists(csv_path):
        print(f"[!] {csv_path} not found.")
        return

    print(f"\n=== S-box dataset analysis: {csv_path} ===\n")
    data = pd.read_csv(csv_path)

    impls = data["implementation"].unique().tolist()
    print("Implementations found:", impls)

    # For this dataset we expect:
    #   "Precomputed_SBox"  -> leaky (with dummy)
    #   "Algebraic_SBox"    -> CT-style
    leaky_name = "Precomputed_SBox" if "Precomputed_SBox" in impls else impls[0]
    safe_name = "Algebraic_SBox" if "Algebraic_SBox" in impls else (
        impls[1] if len(impls) > 1 else impls[0]
    )

    # Mean time per byte value
    data_analysis = (
        data.groupby(["implementation", "byte_value"])["time_ns"]
        .mean()
        .unstack(level=0)
    )
    print("\n---- Mean time for each input (first 20 rows) ----\n")
    print(data_analysis.iloc[0:20])

    # Variance
    variance = data.groupby("implementation")["time_ns"].var()
    print("\n---- Variance Results ----\n")
    print(variance)

    plot_variance_bar(
        variance,
        title="S-box: Variance per implementation",
        filename="sbox_variance_comparison.png",
    )

    # Pairwise t-test
    print("\n------ Welch's t-test (S-box) ------\n")
    leaky_vals = data[data["implementation"] == leaky_name]["time_ns"]
    safe_vals = data[data["implementation"] == safe_name]["time_ns"]
    t_stat, p_val = stats.ttest_ind(leaky_vals, safe_vals, equal_var=False)
    print(f"{leaky_name}  vs  {safe_name}")
    print(f"  T-statistic: {t_stat:.4f}")
    print(f"  P-value    : {p_val:.10e}\n")

    # Correlation per implementation
    print("------ Correlation (byte_value vs time_ns) ------\n")
    for impl in impls:
        subset = data[data["implementation"] == impl]
        correl = subset["byte_value"].corr(subset["time_ns"])
        print(f"{impl}: correlation = {correl:.4f}")
    print("\n")

    # KDE
    plt.figure(figsize=(10, 6))
    sns.kdeplot(
        data=data,
        x="time_ns",
        hue="implementation",
        common_norm=False,
        fill=True,
    )
    plt.title("S-box: Timing Distribution per Implementation")
    plt.xlabel("Time (ns)")
    plt.ylabel("Density")
    plt.grid(axis="x", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("sbox_timing_distribution.png", dpi=150)
    print("KDE plot saved as sbox_timing_distribution.png")
    plt.close()

    # Mean time vs byte
    plt.figure(figsize=(12, 6))
    sns.lineplot(
        data=data,
        x="byte_value",
        y="time_ns",
        hue="implementation",
        estimator="mean",
        errorbar=None,
    )
    plt.title("S-box: Mean Execution Time vs Input Byte")
    plt.xlabel("Byte Value (0–255)")
    plt.ylabel("Time (ns)")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("sbox_mean_time_vs_byte.png", dpi=150)
    print("Plot saved as sbox_mean_time_vs_byte.png")
    plt.close()

    # Detailed leak analysis for Precomputed_SBox (same idea as AES toy)
    print(f"\n------ Detailed Leak Analysis (S-box, {leaky_name}) ------\n")
    vuln_data = data[data["implementation"] == leaky_name]

    group_low = vuln_data[
        (vuln_data["byte_value"] <= 200) & (vuln_data["byte_value"] > 0)
    ]["time_ns"]
    group_high = vuln_data[vuln_data["byte_value"] > 200]["time_ns"]
    group_zero = vuln_data[vuln_data["byte_value"] == 0]["time_ns"]

    print(f"Leaky implementation: {leaky_name}")
    print(f"Mean time (0 < Byte <= 200): {group_low.mean():.2f} ns")
    print(f"Mean time (Byte > 200)     : {group_high.mean():.2f} ns")
    print(f"Difference (High - Low)    : {group_high.mean() - group_low.mean():.2f} ns")

    t_stat_groups, p_val_groups = stats.ttest_ind(
        group_low, group_high, equal_var=False
    )
    print(f"T-statistic (Low vs High): {t_stat_groups:.4f}")
    print(f"P-value (Low vs High)   : {p_val_groups:.10e}")

    print("\nZero Byte Analysis:")
    print(f"Mean time (Byte == 0): {group_zero.mean():.2f} ns")
    print(
        f"Difference vs Low group: {group_zero.mean() - group_low.mean():.2f} ns"
    )

    plt.figure(figsize=(8, 6))
    plot_data = vuln_data.copy()
    plot_data["Group"] = pd.cut(
        plot_data["byte_value"],
        bins=[-1, 0, 200, 256],
        labels=["Zero", "Low", "High"],
    )
    sns.boxplot(data=plot_data, x="Group", y="time_ns")
    plt.title(f"S-box: Time Distribution by Byte Group ({leaky_name})")
    plt.ylabel("Time (ns)")
    plt.tight_layout()
    plt.savefig("sbox_group_distribution.png", dpi=150)
    print("Plot saved as sbox_group_distribution.png")
    plt.close()

    print("\n[Done] S-box dataset analysis.\n")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    # 1) AES toy + PyCryptodome + Safe Toy (if present)
    analyze_aes_dataset("aes_timing_dataset_AZ.csv")

    # 2) Precomputed vs Algebraic S-box (C toy)
    #analyze_sbox_dataset("..\MyTryC\\sbox_precomputed_vs_algebraic_P3.csv")
