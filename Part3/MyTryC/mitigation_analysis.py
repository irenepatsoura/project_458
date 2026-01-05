import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
import itertools

sns.set_theme(style="whitegrid")

# =========================
# 1. Data processing
# =========================

data = pd.read_csv("sbox_precomputed_vs_algebraic_P3_v2.csv")

print("\nImplementations found:", data["implementation"].unique().tolist())

# Mean time per byte per implementation
data_analysis = (
    data.groupby(["implementation", "byte_value"])["time_ns"]
    .mean()
    .unstack(level=0)
)

print("\n----Mean time for each input(ns)----\n")
print(data_analysis.iloc[0:20])

# Variance per implementation
variance = data.groupby("implementation")["time_ns"].var()
print("\n----Variance Results----\n")
print(variance)

# Variance bar plot
plt.figure(figsize=(6, 5))
plt.title("S-box Variance Results")
bars = plt.bar(variance.index, variance.values)
plt.yscale("log")
for bar in bars:
    yval = bar.get_height()
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        yval,
        f"{yval:.6e}",
        va="bottom",
        ha="center",
        fontsize=8,
    )

plt.ylabel("Variance($ns^2$)")
plt.xticks(rotation=15, ha="right")
plt.tight_layout()
plt.savefig("sbox_variance_comparison.png", dpi=150)
print("\nPlot saved as sbox_variance_comparison.png")
plt.close()

# =========================
# 2. Statistical tests
# =========================

# Try to pick leaky/safe by common names; fall back if not present
impls = data["implementation"].unique().tolist()

leaky_name = "Precomputed_SBox" if "Precomputed_SBox" in impls else impls[0]
safe_name = "Algebraic_SBox" if "Algebraic_SBox" in impls else (impls[1] if len(impls) > 1 else impls[0])

# Welch's t-test (highlighted)
leaky_vals = data[data["implementation"] == leaky_name]["time_ns"]
safe_vals = data[data["implementation"] == safe_name]["time_ns"]
t_stat, p_value = stats.ttest_ind(leaky_vals, safe_vals, equal_var=False)

print(f"\n------ Statistical Test Results ({leaky_name} vs {safe_name}) ------\n")
print(f"T-statistic: {t_stat:.4f}")
print(f"P-value    : {p_value:.10e}")

# Pairwise Welch t-tests (like your earlier larger script)
print("\n------ Pairwise Welch's t-tests (all implementations) ------\n")
for a, b in itertools.combinations(impls, 2):
    a_vals = data[data["implementation"] == a]["time_ns"]
    b_vals = data[data["implementation"] == b]["time_ns"]
    t_stat_ab, p_val_ab = stats.ttest_ind(a_vals, b_vals, equal_var=False)
    print(f"{a} vs {b}")
    print(f"  T-statistic: {t_stat_ab:.4f}")
    print(f"  P-value    : {p_val_ab:.10e}\n")

# Correlation between inputs and time
print("\n------ Correlation (byte_value vs time_ns) ------\n")
for impl in impls:
    subset = data[data["implementation"] == impl]
    correl = subset["byte_value"].corr(subset["time_ns"])
    print(f"Correlation for {impl}: {correl:.4f}")

# KDE timing distribution
plt.figure(figsize=(10, 6))
sns.kdeplot(
    data=data,
    x="time_ns",
    hue="implementation",
    fill=True,
    common_norm=False,
)
plt.title("S-box Timing Distribution")
plt.xlabel("Time(ns)")
plt.ylabel("Density")
plt.grid(axis="x", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("sbox_timing_plot.png", dpi=150)
print("\nPlot saved as sbox_timing_plot.png")
plt.close()

# =========================
# 3. Detailed Leak Analysis
# =========================

print("\n------ Detailed Leak Analysis ------\n")

# Mean time vs byte value
plt.figure(figsize=(12, 6))
try:
    sns.lineplot(
        data=data,
        x="byte_value",
        y="time_ns",
        hue="implementation",
        estimator="mean",
        errorbar=None,
    )
except TypeError:
    sns.lineplot(
        data=data,
        x="byte_value",
        y="time_ns",
        hue="implementation",
        estimator="mean",
        ci=None,
    )

plt.title("S-box Mean Execution Time vs Input Byte Value")
plt.xlabel("Byte Value")
plt.ylabel("Time (ns)")
plt.grid(True, linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("sbox_mean_time_vs_byte.png", dpi=150)
print("Plot saved as sbox_mean_time_vs_byte.png")
plt.close()

# Same threshold logic as your AES example
THRESH = 200
vuln_data = data[data["implementation"] == leaky_name]

group_low = vuln_data[(vuln_data["byte_value"] <= THRESH) & (vuln_data["byte_value"] > 0)]["time_ns"]
group_high = vuln_data[vuln_data["byte_value"] > THRESH]["time_ns"]

print(f"\nLeaky Implementation Analysis ({leaky_name}):")
print(f"Mean time (0 < Byte <= {THRESH}): {group_low.mean():.2f} ns")
print(f"Mean time (Byte > {THRESH})     : {group_high.mean():.2f} ns")
print(f"Difference                     : {group_high.mean() - group_low.mean():.2f} ns")

t_stat_groups, p_val_groups = stats.ttest_ind(group_low, group_high, equal_var=False)
print(f"T-statistic (Low vs High): {t_stat_groups:.4f}")
print(f"P-value (Low vs High)   : {p_val_groups:.10e}")

# Zero byte special case
group_zero = vuln_data[vuln_data["byte_value"] == 0]["time_ns"]
print(f"\nZero Byte Analysis:")
print(f"Mean time (Byte == 0): {group_zero.mean():.2f} ns")
print(f"Difference vs Low group: {group_zero.mean() - group_low.mean():.2f} ns")

# Boxplot by groups
plt.figure(figsize=(8, 6))
plot_data = vuln_data.copy()
plot_data["Group"] = pd.cut(
    plot_data["byte_value"],
    bins=[-1, 0, THRESH, 256],
    labels=["Zero", "Low", "High"],
)
sns.boxplot(data=plot_data, x="Group", y="time_ns")
plt.title(f"S-box Distribution of Execution Time by Byte Group ({leaky_name})")
plt.ylabel("Time (ns)")
plt.tight_layout()
plt.savefig("sbox_group_distribution.png", dpi=150)
print("Plot saved as sbox_group_distribution.png")
plt.close()

############################### MY PART ##############################
# =========================
# 3b. Group distribution for the "safe" algebraic implementation
# =========================

safe_data = data[data["implementation"] == safe_name]

group_low_safe = safe_data[(safe_data["byte_value"] <= THRESH) & (safe_data["byte_value"] > 0)]["time_ns"]
group_high_safe = safe_data[safe_data["byte_value"] > THRESH]["time_ns"]
group_zero_safe = safe_data[safe_data["byte_value"] == 0]["time_ns"]

print(f"\nSafe Implementation Analysis ({safe_name}):")
print(f"Mean time (0 < Byte <= {THRESH}): {group_low_safe.mean():.2f} ns")
print(f"Mean time (Byte > {THRESH})     : {group_high_safe.mean():.2f} ns")
print(f"Difference                     : {group_high_safe.mean() - group_low_safe.mean():.2f} ns")

t_stat_groups_safe, p_val_groups_safe = stats.ttest_ind(group_low_safe, group_high_safe, equal_var=False)
print(f"T-statistic (Low vs High): {t_stat_groups_safe:.4f}")
print(f"P-value (Low vs High)   : {p_val_groups_safe:.10e}")

print(f"\nSafe Zero Byte Analysis:")
print(f"Mean time (Byte == 0): {group_zero_safe.mean():.2f} ns")
print(f"Difference vs Low group: {group_zero_safe.mean() - group_low_safe.mean():.2f} ns")

# Boxplot for safe implementation by groups
plt.figure(figsize=(8, 6))
plot_data_safe = safe_data.copy()
plot_data_safe["Group"] = pd.cut(
    plot_data_safe["byte_value"],
    bins=[-1, 0, THRESH, 256],
    labels=["Zero", "Low", "High"],
)
sns.boxplot(data=plot_data_safe, x="Group", y="time_ns")
plt.title(f"S-box Distribution of Execution Time by Byte Group ({safe_name})")
plt.ylabel("Time (ns)")
plt.tight_layout()
plt.savefig("sbox_group_distribution_safe.png", dpi=150)
print("Plot saved as sbox_group_distribution_safe.png")
plt.close()

