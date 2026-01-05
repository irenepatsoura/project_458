import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

CSV_PATH = "sbox_precomputed_vs_algebraic_P3_v2.csv"


def load_dataset(csv_path=CSV_PATH):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"{csv_path} not found. Run the C program first to generate it."
        )
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows.")
    return df


def summarize_stats(df: pd.DataFrame):
    """
    Print basic stats per implementation:
      - mean time_ns
      - std dev
      - relative std dev (%)
    """
    print("\n=== Summary stats per implementation (time_ns in nanoseconds) ===")
    for impl in df["implementation"].unique():
        sub = df[df["implementation"] == impl]["time_ns"]
        mean = sub.mean()
        std = sub.std()
        rel = (std / mean * 100.0) if mean != 0 else 0.0
        print(f"{impl:18s} mean = {mean:10.3f} ns, "
              f"std = {std:10.3f} ns, rel.std = {rel:6.2f}%")
    print("================================================================\n")


def find_largest_differences(df: pd.DataFrame, top_n: int = 10):
    """
    For each byte_value, compare Precomputed_SBox vs Algebraic_SBox:

      - mean_pre, std_pre
      - mean_alg, std_alg
      - diff      = mean_pre - mean_alg
      - pooled_sd = sqrt((std_pre^2 + std_alg^2) / 2)
      - effect    = |diff| / pooled_sd   (large ⇒ difference >> noise)

    Prints the top N byte values by |effect|.
    """
    stats = (
        df.groupby(["implementation", "byte_value"])["time_ns"]
          .agg(["mean", "std", "count"])
          .reset_index()
    )

    pre_stats = stats[stats["implementation"] == "Precomputed_SBox"].copy()
    alg_stats = stats[stats["implementation"] == "Algebraic_SBox"].copy()

    merged = pd.merge(
        pre_stats,
        alg_stats,
        on="byte_value",
        suffixes=("_pre", "_alg")
    )

    merged["diff"] = merged["mean_pre"] - merged["mean_alg"]
    merged["pooled_std"] = np.sqrt(
        (merged["std_pre"] ** 2 + merged["std_alg"] ** 2) / 2.0
    )
    merged["effect"] = merged["diff"].abs() / merged["pooled_std"].replace(0, np.nan)

    merged_sorted = merged.sort_values("effect", ascending=False)

    print("\n=== Byte values with largest Precomputed vs Algebraic differences ===")
    print("(sorted by |diff| / pooled_std)")
    print(
        f"{'byte':>4s} | {'mean_pre(ns)':>12s} | {'mean_alg(ns)':>12s} | "
        f"{'diff(ns)':>10s} | {'pooled_std':>10s} | {'effect':>8s}"
    )
    print("-" * 70)
    for _, row in merged_sorted.head(top_n).iterrows():
        print(
            f"{int(row['byte_value']):4d} | "
            f"{row['mean_pre']:12.3f} | "
            f"{row['mean_alg']:12.3f} | "
            f"{row['diff']:10.3f} | "
            f"{row['pooled_std']:10.3f} | "
            f"{row['effect']:8.3f}"
        )
    print("====================================================================\n")

    return merged_sorted


def make_plots(df: pd.DataFrame, output_prefix="sbox_pre_vs_alg"):
    sns.set_theme(style="whitegrid")

    summary = df.groupby(["implementation", "byte_value"])["time_ns"].mean().reset_index()

    pre = summary[summary["implementation"] == "Precomputed_SBox"]
    alg = summary[summary["implementation"] == "Algebraic_SBox"]

    # ✅ Compute shared y-limits (same y scale for both subplots)
    global_min = min(pre["time_ns"].min(), alg["time_ns"].min())
    global_max = max(pre["time_ns"].max(), alg["time_ns"].max())
    y_min = global_min * 0.95
    y_max = global_max * 1.05

    # ---------------- PLOT 1: Side-by-side line plots ----------------
    plt.figure(figsize=(14, 5))

    # Precomputed S-box
    plt.subplot(1, 2, 1)
    plt.plot(pre["byte_value"], pre["time_ns"], color="red", alpha=0.8)
    plt.title("Precomputed S-Box (table lookup)")
    plt.xlabel("Input Byte Value (0–255)")
    plt.ylabel("Avg time per call (ns)")
    plt.ylim(y_min, y_max)  # ✅ same y-scale

    # Algebraic S-box
    plt.subplot(1, 2, 2)
    plt.plot(alg["byte_value"], alg["time_ns"], color="green", alpha=0.8)
    plt.title("Algebraic S-Box (computed, fixed work)")
    plt.xlabel("Input Byte Value (0–255)")
    plt.ylabel("Avg time per call (ns)")
    plt.ylim(y_min, y_max)  # ✅ same y-scale

    plt.tight_layout()
    out1 = f"{output_prefix}_comparison.png"
    plt.savefig(out1, dpi=150)
    print(f"Saved side-by-side plot to {out1}")

    # ---------------- PLOT 2: Overlay scatter plot ----------------
    plt.figure(figsize=(12, 6))
    sns.scatterplot(
        data=summary,
        x="byte_value",
        y="time_ns",
        hue="implementation",
        style="implementation",
        palette={
            "Precomputed_SBox": "red",
            "Algebraic_SBox": "green",
        },
        s=40,
    )
    plt.title("Timing vs first plaintext byte\nPrecomputed vs Algebraic S-Box")
    plt.xlabel("Input Byte Value (first byte)")
    plt.ylabel("Avg time per call (ns)")
    plt.legend(title="Implementation")

    out2 = f"{output_prefix}_overlay.png"
    plt.savefig(out2, dpi=150)
    print(f"Saved overlay plot to {out2}")

    # ---------------- PLOT 3: Difference vs byte_value ----------------
    stats = (
        df.groupby(["implementation", "byte_value"])["time_ns"]
          .agg(["mean"])
          .reset_index()
    )
    pre_stats = stats[stats["implementation"] == "Precomputed_SBox"].copy()
    alg_stats = stats[stats["implementation"] == "Algebraic_SBox"].copy()
    merged = pd.merge(
        pre_stats,
        alg_stats,
        on="byte_value",
        suffixes=("_pre", "_alg")
    )
    merged["diff"] = merged["mean_pre"] - merged["mean_alg"]

    plt.figure(figsize=(12, 4))
    plt.plot(merged["byte_value"], merged["diff"], alpha=0.8)
    plt.axhline(0, color="black", linewidth=0.8)
    plt.title("Mean timing difference per byte\n(Precomputed - Algebraic)")
    plt.xlabel("Input Byte Value (0–255)")
    plt.ylabel("Diff in mean time (ns)")
    plt.grid(True, linestyle="--", alpha=0.5)
    out3 = f"{output_prefix}_diff.png"
    plt.savefig(out3, dpi=150)
    print(f"Saved diff plot to {out3}")

    plt.show()


def main():
    df = load_dataset()
    summarize_stats(df)
    _ = find_largest_differences(df, top_n=10)
    make_plots(df)


if __name__ == "__main__":
    main()
