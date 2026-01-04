import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

CSV_PATH = "sbox_precomputed_vs_algebraic_P3.csv"


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


def make_plots(df: pd.DataFrame, output_prefix="sbox_pre_vs_alg"):
    sns.set_theme(style="whitegrid")

    # Group by implementation + byte_value to get mean timing per byte
    summary = df.groupby(["implementation", "byte_value"])["time_ns"].mean().reset_index()

    pre = summary[summary["implementation"] == "Precomputed_SBox"]
    alg = summary[summary["implementation"] == "Algebraic_SBox"]

    # ---------------- PLOT 1: Side-by-side line plots ----------------
    plt.figure(figsize=(14, 5))

    # Precomputed S-box (leaky)
    plt.subplot(1, 2, 1)
    plt.plot(pre["byte_value"], pre["time_ns"], color="red", alpha=0.8)
    plt.title("Precomputed S-Box (table + leaky dummy)")
    plt.xlabel("Input Byte Value (0–255)")
    plt.ylabel("Avg time per call (ns)")

    # Algebraic S-box (CT-style)
    plt.subplot(1, 2, 2)
    plt.plot(alg["byte_value"], alg["time_ns"], color="green", alpha=0.8)
    plt.title("Algebraic S-Box (computed, fixed work)")
    plt.xlabel("Input Byte Value (0–255)")
    plt.ylabel("Avg time per call (ns)")

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

    plt.show()


def main():
    df = load_dataset()
    summarize_stats(df)
    make_plots(df)


if __name__ == "__main__":
    main()
