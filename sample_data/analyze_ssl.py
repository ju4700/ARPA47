import csv
import collections
from pathlib import Path

log_path = Path("D:/Development/ARPA47/sample_data/local_ssl_sample.log")

snis = collections.Counter()
tls_versions = collections.Counter()
ciphers = collections.Counter()
curves = collections.Counter()
total_records = 0

with open(log_path, "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("#"):
            continue
        parts = line.strip().split("\t")
        if len(parts) < 10:
            continue
            
        total_records += 1
        version = parts[6]
        cipher = parts[7]
        curve = parts[8]
        sni = parts[9]
        
        if version and version != "-":
            tls_versions[version] += 1
        if cipher and cipher != "-":
            ciphers[cipher] += 1
        if curve and curve != "-":
            curves[curve] += 1
        if sni and sni != "-":
            snis[sni] += 1

print("=== ZEEK SSL LOG ANALYSIS SAMPLE ===")
print(f"Total Connections Analyzed: {total_records:,}")
print("\n--- Top 10 Requested Server Names (SNI) ---")
for k, v in snis.most_common(10):
    print(f"{k}: {v:,} ({v/total_records*100:.1f}%)")

print("\n--- TLS Version Adoption ---")
for k, v in tls_versions.most_common(5):
    print(f"{k}: {v:,} ({v/total_records*100:.1f}%)")
    
print("\n--- Top Cipher Suites ---")
for k, v in ciphers.most_common(5):
    print(f"{k}: {v:,} ({v/total_records*100:.1f}%)")

print("\n--- Top Elliptic Curves (Key Exchange) ---")
for k, v in curves.most_common(5):
    print(f"{k}: {v:,} ({v/total_records*100:.1f}%)")
