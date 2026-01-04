import time
import os
import random
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from aes_implementations import VulnerableAES, SafeAES, measure_time

# =============================================================================
# 1. DATA GENERATION
# =============================================================================

def generate_dataset():
    print("--- Starting AES Side-Channel Data Collection ---")
    
    # Configuration
    # Use a NULL KEY so that Plaintext == State (before S-Box).
    # This ensures our simple analysis (which looks at Plaintext byte values)
    # remains valid even though the leak is technically on (Plaintext ^ Key).
    KEY = bytes([0] * 16)
    safe_aes = SafeAES(KEY)
    vuln_aes = VulnerableAES(KEY)
    
    # Parameters
    # We test every possible value for the first byte (0-255)
    # to see if the value of the byte affects the speed.
    SAMPLES_PER_BYTE = 50      # How many random plaintexts per byte value
    LOOPS_PER_MEASURE = 500    # How many encryptions inside the timer
    
    data_records = []

    print(f"Collecting data for {256} byte values...")
    
    for byte_val in range(256):
        if byte_val % 50 == 0: print(f"Progress: {byte_val}/255")
        
        for i in range(SAMPLES_PER_BYTE):
            # Generate Fixed Plaintext (to reduce noise from other bytes)
            # We use a "fast" value (e.g. 1) for bytes 1-15 to minimize background latency.
            # If we used 0, it would trigger the "Very Slow" path for all padding bytes,
            # drowning out the signal from the first byte.
            pt = bytearray([1] * 16)
            # FIX the first byte (Controlled Input)
            pt[0] = byte_val
            plaintext = bytes(pt)
            
            # 1. Measure Vulnerable Implementation
            t_vuln = measure_time(vuln_aes.encrypt, plaintext, LOOPS_PER_MEASURE)
            data_records.append({
                "implementation": "Vulnerable (Naive)",
                "byte_value": byte_val,
                "time_ns": t_vuln,
                "sample_id": i
            })
            
            # 2. Measure Safe Implementation
            t_safe = measure_time(safe_aes.encrypt, plaintext, LOOPS_PER_MEASURE)
            data_records.append({
                "implementation": "Safe (PyCryptodome)",
                "byte_value": byte_val,
                "time_ns": t_safe,
                "sample_id": i
            })
            
    print("Data collection complete.")
    
    # Convert to DataFrame
    df = pd.DataFrame(data_records)
    
    # Export to CSV (Deliverable requirement)
    csv_filename = "aes_timing_dataset.csv"
    df.to_csv(csv_filename, index=False)
    print(f"Dataset saved to: {csv_filename}")
    
    return df

# =============================================================================
# 4. ANALYSIS & VISUALIZATION
# =============================================================================

def analyze_and_plot(df):
    print("Generating Comparison Plots...")
    sns.set_theme(style="whitegrid")

    # Group by implementation and byte_value to get mean times
    summary = df.groupby(['implementation', 'byte_value'])['time_ns'].mean().reset_index()

    # --- PLOT 1: Side-by-Side Comparison ---
    # This clearly shows the Safe one is flat, and the Vulnerable one is messy
    
    plt.figure(figsize=(14, 6))
    
    # Plot Safe
    plt.subplot(1, 2, 1)
    safe_data = summary[summary['implementation'] == 'Safe (PyCryptodome)']
    plt.plot(safe_data['byte_value'], safe_data['time_ns'], color='green', alpha=0.8)
    plt.title("Safe AES (Constant Time)")
    plt.xlabel("Input Byte Value (0-255)")
    plt.ylabel("Avg Execution Time (ns)")
    plt.ylim(safe_data['time_ns'].min() * 0.95, safe_data['time_ns'].max() * 1.05)

    # Plot Vulnerable
    plt.subplot(1, 2, 2)
    vuln_data = summary[summary['implementation'] == 'Vulnerable (Naive)']
    plt.plot(vuln_data['byte_value'], vuln_data['time_ns'], color='red', alpha=0.8)
    plt.title("Vulnerable AES (Data-Dependent)")
    plt.xlabel("Input Byte Value (0-255)")
    plt.ylabel("Avg Execution Time (ns)")
    
    # Highlight the "Leak"
    plt.tight_layout()
    plt.savefig("aes_comparison_plot.png")
    print("Saved plot: aes_comparison_plot.png")

    # --- PLOT 2: Overlay Scatter Plot ---
    plt.figure(figsize=(12, 6))
    sns.scatterplot(
        data=summary, 
        x='byte_value', 
        y='time_ns', 
        hue='implementation', 
        style='implementation',
        palette={'Safe (PyCryptodome)': 'green', 'Vulnerable (Naive)': 'red'},
        s=40
    )
    plt.title("Timing Correlation: Safe vs Vulnerable Implementation")
    plt.xlabel("Input Byte Value (First Byte of Plaintext)")
    plt.ylabel("Time (ns)")
    plt.legend(title="Implementation")
    
    # Note: We normalize the Y-axis range in the description because the raw 
    # Python times might differ significantly in magnitude.
    plt.savefig("aes_overlay_plot.png")
    print("Saved plot: aes_overlay_plot.png")
    
    plt.show()

# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    # Check if dataset exists, if not generate it
    if not os.path.exists("aes_timing_dataset.csv"):
        dataset = generate_dataset()
    else:
        print("Loading existing dataset from CSV...")
        dataset = pd.read_csv("aes_timing_dataset.csv")
    
    analyze_and_plot(dataset)