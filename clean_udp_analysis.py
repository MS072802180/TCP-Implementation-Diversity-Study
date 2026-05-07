"""
UDP ANALYSIS - ONLY DATA, NO CONCLUSIONS
Prints only what the data contains. No interpretation.
"""

from scapy.all import rdpcap, UDP, IP, TCP
import os
import glob
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

print("="*70)
print("UDP DATA EXTRACTION - RAW RESULTS ONLY")
print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)

pcap_folder = os.path.join(os.getcwd(), "wireshark files")

if not os.path.exists(pcap_folder):
    print(f"\nERROR: Folder not found: {pcap_folder}")
    exit()

pcap_files = []
for ext in ['*.pcap', '*.pcapng', '*.cap']:
    pcap_files.extend(glob.glob(os.path.join(pcap_folder, ext)))

print(f"\nFiles found: {len(pcap_files)}")

# Data collection
src_ports = Counter()
dst_ports = Counter()
payload_sizes = []
packet_times = []
ip_addresses = Counter()
packet_lengths = []
udp_count = 0
tcp_count = 0
other_count = 0

# Check for specific fields
has_mss = False
has_window_scale = False
has_sack = False
has_timestamps = False
has_nop = False
has_eol = False

for idx, pcap_path in enumerate(pcap_files, 1):
    print(f"Processing: {os.path.basename(pcap_path)} ({idx}/{len(pcap_files)})")
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"   Error: {e}")
        continue
    
    for pkt in packets:
        if UDP in pkt:
            udp_count += 1
            udp = pkt[UDP]
            
            src_ports[udp.sport] += 1
            dst_ports[udp.dport] += 1
            
            total_len = len(udp)
            payload = total_len - 8
            payload_sizes.append(payload)
            
            if IP in pkt:
                packet_lengths.append(len(pkt))
                ip_addresses[pkt[IP].src] += 1
            
            if hasattr(pkt, 'time'):
                packet_times.append(pkt.time)
            
            # Check each UDP packet for TCP-like fields
            # This is discovering, not assuming
            for attr in dir(udp):
                attr_lower = attr.lower()
                if 'mss' in attr_lower:
                    has_mss = True
                if 'window' in attr_lower and 'scale' in attr_lower:
                    has_window_scale = True
                if 'sack' in attr_lower:
                    has_sack = True
                if 'timestamp' in attr_lower:
                    has_timestamps = True
                if attr_lower == 'nop':
                    has_nop = True
                if attr_lower == 'eol':
                    has_eol = True
        
        elif TCP in pkt:
            tcp_count += 1
        else:
            other_count += 1

print("\n" + "="*70)
print("RAW DATA - WHAT WAS FOUND")
print("="*70)

print(f"\nTotal packets: {tcp_count + udp_count + other_count:,}")
print(f"TCP packets: {tcp_count:,}")
print(f"UDP packets: {udp_count:,}")
print(f"Other packets: {other_count:,}")

print(f"\nUDP header fields found (from Scapy object):")
if udp_count > 0:
    print(f"   Source port: EXISTS (values from {min(src_ports.keys())} to {max(src_ports.keys())})")
    print(f"   Destination port: EXISTS (values from {min(dst_ports.keys())} to {max(dst_ports.keys())})")
    print(f"   Length: EXISTS")
    print(f"   Checksum: EXISTS")
else:
    print("   No UDP packets found to analyze")

print(f"\nTCP-like options found in UDP packets:")
print(f"   MSS field found: {has_mss}")
print(f"   Window Scale field found: {has_window_scale}")
print(f"   SACK field found: {has_sack}")
print(f"   Timestamp field found: {has_timestamps}")
print(f"   NOP field found: {has_nop}")
print(f"   EOL field found: {has_eol}")

if dst_ports:
    print(f"\nDestination ports found: {len(dst_ports)} unique values")
    print(f"Top 10 destination ports:")
    for port, count in dst_ports.most_common(10):
        print(f"   {port}: {count}")

if src_ports:
    print(f"\nSource ports found: {len(src_ports)} unique values")
    print(f"Top 10 source ports:")
    for port, count in src_ports.most_common(10):
        print(f"   {port}: {count}")

if payload_sizes:
    non_zero = [s for s in payload_sizes if s > 0]
    print(f"\nPayload sizes:")
    print(f"   Minimum: {min(payload_sizes)} bytes")
    print(f"   Maximum: {max(payload_sizes)} bytes")
    print(f"   Average: {sum(payload_sizes)/len(payload_sizes):.1f} bytes")
    print(f"   Zero-payload packets: {payload_sizes.count(0)}")

if packet_lengths:
    print(f"\nPacket sizes (including IP header):")
    print(f"   Minimum: {min(packet_lengths)} bytes")
    print(f"   Maximum: {max(packet_lengths)} bytes")
    print(f"   Average: {sum(packet_lengths)/len(packet_lengths):.1f} bytes")

if packet_times:
    time_buckets = defaultdict(int)
    for t in packet_times:
        time_buckets[int(t)] += 1
    print(f"\nTraffic timing:")
    print(f"   Time range: {min(time_buckets.keys())} to {max(time_buckets.keys())} seconds")
    print(f"   Peak packets per second: {max(time_buckets.values())}")

if ip_addresses:
    print(f"\nUnique source IP addresses: {len(ip_addresses)}")
    print(f"Top 5 source IPs:")
    for ip, count in ip_addresses.most_common(5):
        print(f"   {ip}: {count}")

# Create figures (just the data, no conclusions on images)
figures_dir = "udp_data_figures"
os.makedirs(figures_dir, exist_ok=True)

# Figure 1: Destination ports
if dst_ports:
    fig1, ax1 = plt.subplots(figsize=(12, 5))
    top_ports = dst_ports.most_common(20)
    ax1.bar(range(len(top_ports)), [c for _, c in top_ports], color='steelblue')
    ax1.set_xticks(range(len(top_ports)))
    ax1.set_xticklabels([str(p) for p, _ in top_ports], rotation=45, ha='right', fontsize=8)
    ax1.set_ylabel('Packet Count')
    ax1.set_title('UDP Destination Port Distribution')
    ax1.set_yscale('log')
    plt.tight_layout()
    plt.savefig(f'{figures_dir}/udp_destination_ports.png', dpi=150)
    print(f"\nFigure saved: {figures_dir}/udp_destination_ports.png")

# Figure 2: Payload sizes
if payload_sizes and any(s > 0 for s in payload_sizes):
    fig2, ax2 = plt.subplots(figsize=(10, 4))
    ax2.hist([s for s in payload_sizes if s > 0], bins=50, color='coral', edgecolor='black')
    ax2.set_xlabel('Payload Size (bytes)')
    ax2.set_ylabel('Packet Count')
    ax2.set_title('UDP Payload Size Distribution')
    ax2.set_yscale('log')
    plt.tight_layout()
    plt.savefig(f'{figures_dir}/udp_payload_sizes.png', dpi=150)
    print(f"Figure saved: {figures_dir}/udp_payload_sizes.png")

# Figure 3: Protocol distribution
fig3, ax3 = plt.subplots(figsize=(6, 6))
protocols = ['TCP', 'UDP', 'Other']
counts = [tcp_count, udp_count, other_count]
colors = ['#2ecc71', '#e74c3c', '#95a5a6']
ax3.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors, startangle=90)
ax3.set_title('Protocol Distribution (Packet Count)')
plt.tight_layout()
plt.savefig(f'{figures_dir}/protocol_distribution.png', dpi=150)
print(f"Figure saved: {figures_dir}/protocol_distribution.png")

print("\n" + "="*70)
print("DATA EXTRACTION COMPLETE")
print("="*70)
print("\nThe above numbers are from your data. No conclusions have been drawn.")
print("You can now interpret these numbers yourself.")