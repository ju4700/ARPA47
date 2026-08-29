import gzip
import csv

print("--- ZEEK SSL LOG SAMPLE ---")
with gzip.open(r"D:\Development\ARPA47\sample_data\sample_ssl.log.gz", "rt", encoding="utf-8") as f:
    for i in range(10):
        line = f.readline().strip()
        if not line.startswith('#'):
            parts = line.split('\t')
            if len(parts) > 10:
                print(f"Time: {parts[0]}, IP: {parts[2]}, SNI: {parts[9]}, TLS: {parts[6]}, Cipher: {parts[7]}")

print("\n--- NETFLOW CSV SAMPLE ---")
with open(r"D:\Development\ARPA47\sample_data\sample_netflow.csv", "r", encoding="utf-8") as f:
    for _ in range(5):
        print(f.readline().strip())
