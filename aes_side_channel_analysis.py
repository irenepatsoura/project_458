import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy import stats

# 1. Data processing

data = pd.read_csv("aes_timing_dataset.csv")

# Group data based on implementation and byte value
# The goal is to see the mean time for each input
data_analysis = data.groupby(['implementation','byte_value'])['time_ns'].mean().unstack(level=0)
# First few rows
#print(data_analysis.head())
print('\n----Mean time for each input(ns)----\n')
print(data_analysis.iloc[0:20])

# Variance calculation for both implementations
variance = data.groupby('implementation')['time_ns'].var()
print('\n----Variance Results----\n')
print(variance)

# Visualize variance results
plt.figure(figsize=(6,5))
plt.title('Variance Results')
bars = plt.bar(variance.index, variance.values, color=['blue','green'])
plt.yscale('log')
# Add raw values on top of the bars
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x()+bar.get_width()/3, yval, f'{yval:.6e}',
             va='bottom',ha='center')

plt.ylabel('Variance($ns^2$)')
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig('variance_comparison.png')
print('\nPlot saved as variance_comparison.png')
# plt.show()

# 2. Statistical tests

# Welch's t-Test
# Get timing data for each implementation
safe_impl = data[data['implementation'] == 'Safe (PyCryptodome)']['time_ns']
vuln_impl = data[data['implementation'] == 'Vulnerable (Naive)']['time_ns']

# Perform the test
t_stat , p_value = stats.ttest_ind(safe_impl,vuln_impl,equal_var=False)

# Print the results
print(f'\n------ Statistical Test Results ------\n')
print(f'T-statistic:{t_stat:.4f}')
print(f'P-value:{p_value:.10e}')

# Correlation between inputs and time
print('\n-----------------------------\n')
for impl in ['Safe (PyCryptodome)','Vulnerable (Naive)']:
    subset = data[data['implementation'] == impl]
    correl = subset['byte_value'].corr(subset['time_ns'])
    print(f'\nCorrelation for {impl}: {correl:.4f}')

# Visualization of results
plt.figure(figsize=(10,6))
sns.kdeplot(data=data,x='time_ns',hue='implementation',palette=['blue','green'],fill=True,common_norm=False)
plt.title('Timing Distribution')
plt.xlabel('Time(ns)')
plt.ylabel('Density')
plt.grid(axis='x',linestyle='--',alpha=0.5)
plt.tight_layout()
plt.savefig('timing_plot.png')
print('\nPlot saved as timing_plot.png')
# plt.show()

# 3. Detailed Leak Analysis (Part 3 Insights)

print('\n------ Detailed Leak Analysis ------\n')

# Plot Mean Time vs Byte Value to visualize the leak pattern
plt.figure(figsize=(12, 6))
sns.lineplot(data=data, x='byte_value', y='time_ns', hue='implementation', palette=['blue', 'green'])
plt.title('Mean Execution Time vs Input Byte Value')
plt.xlabel('Byte Value')
plt.ylabel('Time (ns)')
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig('mean_time_vs_byte.png')
print('Plot saved as mean_time_vs_byte.png')

# Analyze specific groups based on the observed pattern
# We suspect a threshold around 200 based on the simulation logic
vuln_data = data[data['implementation'] == 'Vulnerable (Naive)']
group_low = vuln_data[(vuln_data['byte_value'] <= 200) & (vuln_data['byte_value'] > 0)]['time_ns']
group_high = vuln_data[vuln_data['byte_value'] > 200]['time_ns']

print(f'\nVulnerable Implementation Analysis:')
print(f'Mean time (0 < Byte <= 200): {group_low.mean():.2f} ns')
print(f'Mean time (Byte > 200): {group_high.mean():.2f} ns')
print(f'Difference: {group_high.mean() - group_low.mean():.2f} ns')

# T-test between these groups
t_stat_groups, p_val_groups = stats.ttest_ind(group_low, group_high, equal_var=False)
print(f'T-statistic (Low vs High): {t_stat_groups:.4f}')
print(f'P-value (Low vs High): {p_val_groups:.10e}')

# Check for the "Zero" case special handling
group_zero = vuln_data[vuln_data['byte_value'] == 0]['time_ns']
print(f'\nZero Byte Analysis:')
print(f'Mean time (Byte == 0): {group_zero.mean():.2f} ns')
print(f'Difference vs Low group: {group_zero.mean() - group_low.mean():.2f} ns')

# Boxplot to show distributions of the groups
plt.figure(figsize=(8, 6))
# Create a temporary dataframe for plotting
plot_data = vuln_data.copy()
plot_data['Group'] = pd.cut(plot_data['byte_value'], bins=[-1, 0, 200, 256], labels=['Zero', 'Low', 'High'])
sns.boxplot(data=plot_data, x='Group', y='time_ns')
plt.title('Distribution of Execution Time by Byte Value Group')
plt.ylabel('Time (ns)')
plt.savefig('group_distribution.png')
print('Plot saved as group_distribution.png')
