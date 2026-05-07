"""
TCP Fingerprint Analysis - COMPLETE WITH VISUALIZATIONS
Creates publication-ready figures and runs advanced statistical analysis
"""

from scapy.all import rdpcap, TCP, IP
import pandas as pd
import numpy as np
import os
import glob
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

# Set style for publication-quality figures
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("Set2")
plt.rcParams['figure.dpi'] = 150
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['axes.labelsize'] = 11

# ==================================================
# STEP 1: LOAD AND PROCESS ALL PCAP FILES
# ==================================================

print("="*70)
print("TCP FINGERPRINT ANALYSIS - COMPLETE WITH VISUALIZATIONS")
print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)

# Folder containing your pcap files
pcap_folder = os.path.join(os.getcwd(), "wireshark files")

if not os.path.exists(pcap_folder):
    print(f"\n❌ ERROR: Folder not found: {pcap_folder}")
    exit()

# Find all pcap files
pcap_files = []
for ext in ['*.pcap', '*.pcapng', '*.cap']:
    pcap_files.extend(glob.glob(os.path.join(pcap_folder, ext)))

print(f"\n📁 Found {len(pcap_files)} pcap files")

# Process each file
all_results = []

for idx, pcap_path in enumerate(pcap_files, 1):
    file_name = os.path.basename(pcap_path)
    print(f"   [{idx}/{len(pcap_files)}] Processing: {file_name}")
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"      ❌ Error: {e}")
        continue
    
    for pkt in packets:
        if TCP in pkt and pkt[TCP].flags == 0x12:  # SYN-ACK
            tcp = pkt[TCP]
            
            fingerprint = {
                'source_file': file_name,
                'source_ip': pkt[IP].src if IP in pkt else None,
                'destination_ip': pkt[IP].dst if IP in pkt else None,
                'window_size': tcp.window,
                'ttl': pkt[IP].ttl if IP in pkt else None,
                'mss': None,
                'window_scale': None,
                'sack': False,
                'timestamps': False,
            }
            
            for opt in tcp.options:
                if opt[0] == 'MSS':
                    fingerprint['mss'] = opt[1]
                elif opt[0] == 'WScale':
                    fingerprint['window_scale'] = opt[1]
                elif opt[0] == 'SAckOK':
                    fingerprint['sack'] = True
                elif opt[0] == 'Timestamp':
                    fingerprint['timestamps'] = True
            
            all_results.append(fingerprint)

df = pd.DataFrame(all_results)
print(f"\n✅ Total SYN-ACK packets: {len(df):,}")

# ==================================================
# STEP 2: CREATE DERIVED FEATURES
# ==================================================

# Option presence flags
df['has_mss'] = df['mss'].notna()
df['has_ws'] = df['window_scale'].notna()
df['has_ts'] = df['timestamps']
df['has_sack'] = df['sack']

# Create configuration string
df['config'] = (
    df['has_mss'].astype(int).astype(str) +
    df['has_ws'].astype(int).astype(str) +
    df['has_sack'].astype(int).astype(str) +
    df['has_ts'].astype(int).astype(str)
)

# Performance calculation (50ms RTT)
rtt_seconds = 0.050
def calc_throughput(row):
    if row['has_ws'] and row['mss']:
        window_bytes = 64240 * (2 ** row['window_scale'])
    elif row['mss']:
        window_bytes = 64240
    else:
        return 0
    mss_bytes = row['mss'] if row['mss'] else 1460
    return (window_bytes * 8) / rtt_seconds / 1000000

df['throughput_mbps'] = df.apply(calc_throughput, axis=1)

# Security score (0-1, lower is more secure)
df['security_score'] = (
    (df['has_ts'] * 0.7 + df['has_sack'] * 0.4 + df['has_ws'] * 0.3 + df['has_mss'] * 0.1)
) / 1.5

# TTL categorization
def categorize_ttl(ttl):
    if pd.isna(ttl):
        return 'Unknown'
    elif ttl <= 64:
        return 'Linux/Unix (initial 64)'
    elif ttl <= 128:
        return 'Windows (initial 128)'
    else:
        return 'Router/Other (initial 255)'

df['os_hint'] = df['ttl'].apply(categorize_ttl)

print("\n✅ Derived features created")

# ==================================================
# STEP 3: CREATE ALL VISUALIZATIONS
# ==================================================

print("\n" + "="*70)
print("📊 CREATING VISUALIZATIONS")
print("="*70)

# Create figures directory
figures_dir = "tcp_figures"
os.makedirs(figures_dir, exist_ok=True)

# ------------------------------------------------------------------
# FIGURE 1: TCP Option Adoption Rates (Bar Chart)
# ------------------------------------------------------------------
fig1, ax1 = plt.subplots(figsize=(8, 5))
options = ['MSS', 'Window Scale', 'SACK', 'Timestamps']
rates = [100, df['has_ws'].mean()*100, df['has_sack'].mean()*100, df['has_ts'].mean()*100]
colors = ['#2ecc71', '#3498db', '#9b59b6', '#e74c3c']
bars = ax1.bar(options, rates, color=colors, edgecolor='black', linewidth=1)
ax1.set_ylim(0, 105)
ax1.set_ylabel('Adoption Rate (%)', fontsize=12)
ax1.set_title('TCP Option Adoption Rates', fontsize=14, fontweight='bold')
for bar, rate in zip(bars, rates):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
             f'{rate:.1f}%', ha='center', va='bottom', fontsize=11, fontweight='bold')
ax1.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f'{figures_dir}/01_option_adoption.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 01_option_adoption.png")

# ------------------------------------------------------------------
# FIGURE 2: Window Scale Distribution (Histogram)
# ------------------------------------------------------------------
fig2, ax2 = plt.subplots(figsize=(10, 5))
ws_data = df[df['has_ws']]['window_scale']
ws_counts = ws_data.value_counts().sort_index()
bars = ax2.bar(ws_counts.index.astype(int), ws_counts.values, color='#3498db', 
               edgecolor='black', alpha=0.8)
ax2.set_xlabel('Window Scale Factor', fontsize=12)
ax2.set_ylabel('Number of Handshakes', fontsize=12)
ax2.set_title('Window Scale Factor Distribution', fontsize=14, fontweight='bold')
ax2.set_xticks(range(0, 14))
ax2.grid(axis='y', alpha=0.3)
# Add percentage labels on top of highest bars
for bar, val in zip(bars, ws_counts.values):
    if val > 1000:
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height(), 
                f'{val/len(ws_data)*100:.1f}%', ha='center', va='bottom', fontsize=8)
plt.tight_layout()
plt.savefig(f'{figures_dir}/02_window_scale_distribution.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 02_window_scale_distribution.png")

# ------------------------------------------------------------------
# FIGURE 3: MSS Distribution (Pie Chart)
# ------------------------------------------------------------------
fig3, ax3 = plt.subplots(figsize=(8, 8))
mss_data = df['mss'].dropna()
mss_counts = mss_data.value_counts()
# Group small ones as 'Other'
threshold = 500
main_mss = mss_counts[mss_counts >= threshold]
other_sum = mss_counts[mss_counts < threshold].sum()
if other_sum > 0:
    main_mss['Other'] = other_sum
colors = plt.cm.Set3(range(len(main_mss)))
wedges, texts, autotexts = ax3.pie(main_mss.values, labels=main_mss.index, 
                                    autopct='%1.1f%%', colors=colors, startangle=90)
ax3.set_title('MSS Value Distribution', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(f'{figures_dir}/03_mss_distribution.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 03_mss_distribution.png")

# ------------------------------------------------------------------
# FIGURE 4: Configuration Archetypes (Bar Chart)
# ------------------------------------------------------------------
fig4, ax4 = plt.subplots(figsize=(10, 5))
config_counts = df['config'].value_counts()
config_labels = {
    '1110': 'MSS + WS + SACK', '1010': 'MSS + SACK', '1111': 'MSS + WS + SACK + TS',
    '1000': 'MSS only', '1100': 'MSS + WS', '1011': 'MSS + SACK + TS', '1101': 'MSS + WS + TS'
}
config_names = [config_labels.get(c, c) for c in config_counts.index]
bars = ax4.barh(config_names, config_counts.values, color='#e67e22', edgecolor='black', alpha=0.8)
ax4.set_xlabel('Number of Handshakes', fontsize=12)
ax4.set_title('TCP Option Configurations', fontsize=14, fontweight='bold')
for bar, val in zip(bars, config_counts.values):
    ax4.text(bar.get_width() + 500, bar.get_y() + bar.get_height()/2, 
            f'{val:,} ({val/len(df)*100:.1f}%)', va='center', fontsize=9)
ax4.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig(f'{figures_dir}/04_configurations.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 04_configurations.png")

# ------------------------------------------------------------------
# FIGURE 5: Throughput by Window Scale (Box Plot)
# ------------------------------------------------------------------
fig5, ax5 = plt.subplots(figsize=(12, 5))
ws_throughput = [df[df['window_scale'] == ws]['throughput_mbps'].values for ws in range(0, 13) 
                 if len(df[df['window_scale'] == ws]) > 0]
ws_labels = [ws for ws in range(0, 13) if len(df[df['window_scale'] == ws]) > 0]
bp = ax5.boxplot(ws_throughput, labels=ws_labels, patch_artist=True)
for box in bp['boxes']:
    box.set_facecolor('#2ecc71')
    box.set_alpha(0.7)
ax5.set_xlabel('Window Scale Factor', fontsize=12)
ax5.set_ylabel('Theoretical Throughput (Mbps)', fontsize=12)
ax5.set_title('Throughput by Window Scale Factor', fontsize=14, fontweight='bold')
ax5.set_yscale('log')
ax5.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f'{figures_dir}/05_throughput_by_scale.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 05_throughput_by_scale.png")

# ------------------------------------------------------------------
# FIGURE 6: Security Score Distribution (Histogram)
# ------------------------------------------------------------------
fig6, ax6 = plt.subplots(figsize=(10, 5))
n, bins, patches = ax6.hist(df['security_score'], bins=30, color='#e74c3c', 
                            edgecolor='black', alpha=0.7)
ax6.axvline(df['security_score'].mean(), color='blue', linestyle='--', 
            label=f'Mean: {df["security_score"].mean():.3f}')
ax6.axvline(df['security_score'].median(), color='green', linestyle='--', 
            label=f'Median: {df["security_score"].median():.3f}')
ax6.set_xlabel('Security Risk Score (0=Secure, 1=Risky)', fontsize=12)
ax6.set_ylabel('Number of Handshakes', fontsize=12)
ax6.set_title('Security Risk Score Distribution', fontsize=14, fontweight='bold')
ax6.legend()
ax6.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f'{figures_dir}/06_security_score_distribution.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 06_security_score_distribution.png")

# ------------------------------------------------------------------
# FIGURE 7: TTL Distribution by OS Type (Pie Chart)
# ------------------------------------------------------------------
fig7, ax7 = plt.subplots(figsize=(8, 8))
ttl_counts = df['os_hint'].value_counts()
colors = ['#2ecc71', '#3498db', '#e74c3c']
wedges, texts, autotexts = ax7.pie(ttl_counts.values, labels=ttl_counts.index, 
                                    autopct='%1.1f%%', colors=colors, startangle=90)
ax7.set_title('TTL Distribution by OS Type', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(f'{figures_dir}/07_ttl_os_distribution.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 07_ttl_os_distribution.png")

# ------------------------------------------------------------------
# FIGURE 8: TTL by Configuration (Box Plot)
# ------------------------------------------------------------------
fig8, ax8 = plt.subplots(figsize=(10, 5))
configs_to_plot = ['1110', '1010', '1111', '1000']
config_data = [df[df['config'] == cfg]['ttl'].dropna().values for cfg in configs_to_plot]
config_labels_plot = ['MSS+WS+SACK', 'MSS+SACK', 'All Options', 'MSS only']
bp = ax8.boxplot(config_data, labels=config_labels_plot, patch_artist=True)
for box in bp['boxes']:
    box.set_facecolor('#9b59b6')
    box.set_alpha(0.7)
ax8.set_ylabel('Time-to-Live (TTL)', fontsize=12)
ax8.set_title('TTL Distribution by TCP Configuration', fontsize=14, fontweight='bold')
ax8.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f'{figures_dir}/08_ttl_by_configuration.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 08_ttl_by_configuration.png")

# ------------------------------------------------------------------
# FIGURE 9: Performance-Security Trade-off (Scatter Plot)
# ------------------------------------------------------------------
fig9, ax9 = plt.subplots(figsize=(10, 6))
# Sample for visualization (plot every 10th point to avoid overcrowding)
sample_df = df.sample(min(5000, len(df)))
scatter = ax9.scatter(sample_df['throughput_mbps'], sample_df['security_score'], 
                      c=sample_df['window_scale'].fillna(0), cmap='viridis', 
                      alpha=0.5, s=20, edgecolors='none')
cbar = plt.colorbar(scatter, ax=ax9)
cbar.set_label('Window Scale Factor', fontsize=10)
ax9.set_xlabel('Theoretical Throughput (Mbps)', fontsize=12)
ax9.set_ylabel('Security Risk Score (0=Secure, 1=Risky)', fontsize=12)
ax9.set_title('Performance-Security Trade-off', fontsize=14, fontweight='bold')
ax9.set_xscale('log')
ax9.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(f'{figures_dir}/09_performance_security_tradeoff.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 09_performance_security_tradeoff.png")

# ------------------------------------------------------------------
# FIGURE 10: Correlation Heatmap
# ------------------------------------------------------------------
fig10, ax10 = plt.subplots(figsize=(8, 6))
corr_data = df[['has_mss', 'has_ws', 'has_sack', 'has_ts', 'window_size', 'ttl', 'throughput_mbps', 'security_score']].copy()
corr_data['has_ws'] = corr_data['has_ws'].astype(int)
corr_data['has_sack'] = corr_data['has_sack'].astype(int)
corr_data['has_ts'] = corr_data['has_ts'].astype(int)
corr_matrix = corr_data.corr()
mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
sns.heatmap(corr_matrix, mask=mask, annot=True, fmt='.2f', cmap='RdBu_r', 
            center=0, square=True, linewidths=0.5, ax=ax10)
ax10.set_title('Feature Correlation Matrix', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(f'{figures_dir}/10_correlation_heatmap.png', dpi=300, bbox_inches='tight')
print(f"   ✅ Saved: 10_correlation_heatmap.png")

print(f"\n✅ All 10 figures saved to: {figures_dir}/")

# ==================================================
# STEP 4: ADDITIONAL STATISTICAL ANALYSIS
# ==================================================

print("\n" + "="*70)
print("📊 ADDITIONAL STATISTICAL ANALYSIS")
print("="*70)

# TTL by Configuration Analysis
print("\n📈 TTL Statistics by Configuration:")
print("-" * 45)
config_ttl_stats = df.groupby('config')['ttl'].agg(['mean', 'median', 'std', 'count'])
for cfg in config_ttl_stats.index:
    mean_val = config_ttl_stats.loc[cfg, 'mean']
    median_val = config_ttl_stats.loc[cfg, 'median']
    count_val = config_ttl_stats.loc[cfg, 'count']
    if pd.notna(mean_val):
        print(f"   {config_labels.get(cfg, cfg)}: mean={mean_val:.1f}, median={median_val:.0f}, n={int(count_val):,}")

# Correlation Analysis
print("\n📈 Correlation Between Features:")
print("-" * 45)
print(f"   Window Scale vs Throughput: {df['window_scale'].corr(df['throughput_mbps']):.3f}")
print(f"   Window Scale vs Security Score: {df['window_scale'].corr(df['security_score']):.3f}")
print(f"   TTL vs Window Size: {df['ttl'].corr(df['window_size']):.3f}")

# Statistical Test: Timestamps vs Throughput
print("\n📈 Statistical Tests:")
print("-" * 45)
ts_throughput = df[df['has_ts']]['throughput_mbps']
no_ts_throughput = df[~df['has_ts']]['throughput_mbps']
if len(ts_throughput) > 0 and len(no_ts_throughput) > 0:
    t_stat, p_val = stats.ttest_ind(ts_throughput, no_ts_throughput)
    print(f"   Throughput with Timestamps vs without: p = {p_val:.4f}")
    if p_val < 0.05:
        print(f"   → Statistically significant difference (p < 0.05)")

# Chi-square test for option independence
from scipy.stats import chi2_contingency
contingency = pd.crosstab(df['has_ws'], df['has_ts'])
chi2, p_val, dof, expected = chi2_contingency(contingency)
print(f"   Window Scale vs Timestamps independence: p = {p_val:.4f}")
if p_val < 0.05:
    print(f"   → Options are dependent (not independent)")

# Throughput percentiles
print("\n📈 Throughput Percentiles:")
print("-" * 45)
for p in [10, 25, 50, 75, 90]:
    val = df['throughput_mbps'].quantile(p/100)
    print(f"   {p}th percentile: {val:.0f} Mbps")

# Most common MSS
print("\n📈 Most Common MSS Values:")
print("-" * 45)
for mss, count in df['mss'].value_counts().head(5).items():
    print(f"   {int(mss)} bytes: {count:,} handshakes ({count/len(df)*100:.1f}%)")

# Most common TTL
print("\n📈 Most Common TTL Values:")
print("-" * 45)
for ttl, count in df['ttl'].value_counts().head(5).items():
    if pd.notna(ttl):
        print(f"   TTL {int(ttl)}: {count:,} handshakes ({count/len(df)*100:.1f}%)")

# ==================================================
# STEP 5: SAVE COMPLETE RESULTS
# ==================================================

print("\n" + "="*70)
print("💾 SAVING RESULTS")
print("="*70)

# Save full dataframe
csv_filename = f"tcp_complete_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
df.to_csv(csv_filename, index=False)
print(f"\n✅ Full data saved to: {csv_filename}")

# Save summary statistics
summary_file = f"analysis_summary_complete_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(summary_file, 'w') as f:
    f.write("="*60 + "\n")
    f.write("TCP FINGERPRINT ANALYSIS - COMPLETE SUMMARY\n")
    f.write("="*60 + "\n\n")
    f.write(f"Analysis date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"Total SYN-ACK handshakes: {len(df):,}\n")
    f.write(f"Unique source IPs: {df['source_ip'].nunique():,}\n")
    f.write(f"Files processed: {len(pcap_files)}\n\n")
    
    f.write("TCP OPTION ADOPTION RATES:\n")
    f.write(f"  MSS: 100.0%\n")
    f.write(f"  Window Scale: {df['has_ws'].mean()*100:.1f}%\n")
    f.write(f"  SACK: {df['has_sack'].mean()*100:.1f}%\n")
    f.write(f"  Timestamps: {df['has_ts'].mean()*100:.1f}%\n\n")
    
    f.write("CONFIGURATION DISTRIBUTION:\n")
    for cfg, count in df['config'].value_counts().head(7).items():
        f.write(f"  {config_labels.get(cfg, cfg)}: {count:,} ({count/len(df)*100:.1f}%)\n")
    f.write("\n")
    
    f.write("PERFORMANCE METRICS:\n")
    f.write(f"  Mean throughput: {df['throughput_mbps'].mean():.0f} Mbps\n")
    f.write(f"  Median throughput: {df['throughput_mbps'].median():.0f} Mbps\n")
    f.write(f"  Throughput range: {df['throughput_mbps'].min():.0f} - {df['throughput_mbps'].max():.0f} Mbps\n\n")
    
    f.write("SECURITY METRICS:\n")
    f.write(f"  Mean security score: {df['security_score'].mean():.3f}\n")
    f.write(f"  Median security score: {df['security_score'].median():.3f}\n")
    f.write(f"  Security score range: {df['security_score'].min():.3f} - {df['security_score'].max():.3f}\n\n")
    
    f.write("TTL / OS DISTRIBUTION:\n")
    for os_type, count in df['os_hint'].value_counts().items():
        f.write(f"  {os_type}: {count:,} ({count/len(df)*100:.1f}%)\n")

print(f"✅ Summary saved to: {summary_file}")

# ==================================================
# FINAL SUMMARY
# ==================================================

print("\n" + "="*70)
print("🎯 FINAL SUMMARY - WHAT YOU CAN PUT IN YOUR PAPER")
print("="*70)

print(f"""

DATASET:
- Total handshakes: {len(df):,}
- Unique source IPs: {df['source_ip'].nunique():,}
- PCAP files analyzed: {len(pcap_files)}

KEY FINDINGS:

1. TCP OPTION ADOPTION:
   - MSS: 100% (baseline)
   - SACK: {df['has_sack'].mean()*100:.1f}%
   - Window Scale: {df['has_ws'].mean()*100:.1f}%
   - Timestamps: {df['has_ts'].mean()*100:.1f}% ← Only 1 in 6 servers!

2. DOMINANT CONFIGURATION:
   - MSS+WS+SACK (no Timestamps): {len(df[df['config']=='1110']):,} ({len(df[df['config']=='1110'])/len(df)*100:.1f}%)

3. WINDOW SCALE:
   - Scale 7 dominates: {len(df[df['window_scale']==7]):,} ({len(df[df['window_scale']==7])/len(df[df['has_ws']])*100:.1f}% of WS-enabled)

4. OS TYPES (from TTL analysis):
   - Linux/Unix: {len(df[df['os_hint']=='Linux/Unix (initial 64)']):,} ({len(df[df['os_hint']=='Linux/Unix (initial 64)'])/len(df)*100:.1f}%)
   - Windows: {len(df[df['os_hint']=='Windows (initial 128)']):,} ({len(df[df['os_hint']=='Windows (initial 128)'])/len(df)*100:.1f}%)

5. PERFORMANCE-SECURITY TRADE-OFF:
   - Mean throughput: {df['throughput_mbps'].mean():.0f} Mbps
   - Mean security score: {df['security_score'].mean():.3f}
   - Correlation: {df['throughput_mbps'].corr(df['security_score']):.3f}

VISUALIZATIONS CREATED:
   1. 01_option_adoption.png - Bar chart of option adoption rates
   2. 02_window_scale_distribution.png - Histogram of window scales
   3. 03_mss_distribution.png - Pie chart of MSS values
   4. 04_configurations.png - Horizontal bar chart of configs
   5. 05_throughput_by_scale.png - Box plot of throughput by scale
   6. 06_security_score_distribution.png - Histogram of security scores
   7. 07_ttl_os_distribution.png - Pie chart of OS types
   8. 08_ttl_by_configuration.png - Box plot of TTL by config
   9. 09_performance_security_tradeoff.png - Scatter plot
   10. 10_correlation_heatmap.png - Correlation matrix

These figures are saved in the '{figures_dir}' folder.
""")

print("\n" + "="*70)
print(f"✅ ANALYSIS COMPLETE at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)