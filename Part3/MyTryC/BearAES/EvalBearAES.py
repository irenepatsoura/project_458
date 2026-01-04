import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

def analyze_bearssl_benchmark(csv_path="bearssl_aes_timing.csv"):
    print("Loading BearSSL timing data...")
    df = pd.read_csv(csv_path)

    sns.set_theme(style="whitegrid")

    # Group by implementation and byte_value to get mean times
    summary = df.groupby(['implementation', 'byte_value'])['time_ns'].mean().reset_index()

    big_data   = summary[summary['implementation'] == 'AES_big']
    small_data = summary[summary['implementation'] == 'AES_small']
    ct_data    = summary[summary['implementation'] == 'AES_ct']

    # --- PLOT 1: Side-by-side comparison for all three (line plots) ---
    plt.figure(figsize=(18, 5))

    # AES_big
    plt.subplot(1, 3, 1)
    plt.plot(big_data['byte_value'], big_data['time_ns'],
             color='red', alpha=0.8)
    plt.title("BearSSL AES_big (table-based)")
    plt.xlabel("Input Byte Value (0-255)")
    plt.ylabel("Avg cycles per block")
    if not big_data.empty:
        plt.ylim(big_data['time_ns'].min() * 0.95,
                 big_data['time_ns'].max() * 1.05)

    # AES_small
    plt.subplot(1, 3, 2)
    plt.plot(small_data['byte_value'], small_data['time_ns'],
             color='orange', alpha=0.8)
    plt.title("BearSSL AES_small (small-footprint)")
    plt.xlabel("Input Byte Value (0-255)")
    plt.ylabel("Avg cycles per block")

    # AES_ct
    plt.subplot(1, 3, 3)
    plt.plot(ct_data['byte_value'], ct_data['time_ns'],
             color='green', alpha=0.8)
    plt.title("BearSSL AES_ct (constant-time)")
    plt.xlabel("Input Byte Value (0-255)")
    plt.ylabel("Avg cycles per block")

    plt.tight_layout()
    plt.savefig("bearssl_aes_comparison_plot.png")
    print("Saved plot: bearssl_aes_comparison_plot.png")

    # --- PLOT 2: Overlay scatter plot (like your original) ---
    plt.figure(figsize=(12, 6))
    sns.scatterplot(
        data=summary,
        x='byte_value',
        y='time_ns',
        hue='implementation',
        style='implementation',
        palette={
            'AES_big': 'red',
            'AES_small': 'orange',
            'AES_ct': 'green',
        },
        s=40
    )
    plt.title("BearSSL timing: AES_big vs AES_small vs AES_ct")
    plt.xlabel("Input Byte Value (first byte of plaintext)")
    plt.ylabel("Avg cycles per block")
    plt.legend(title="Implementation")

    plt.savefig("bearssl_aes_overlay_plot.png")
    print("Saved plot: bearssl_aes_overlay_plot.png")

    plt.show()

if __name__ == "__main__":
    analyze_bearssl_benchmark()
