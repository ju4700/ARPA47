import collections
import sys

LIVE_LOG = '/data/arpa/zeek_logs/ssl.log'
tls = collections.Counter()
curves = collections.Counter()
snis = collections.Counter()
total_records = 0

try:
    with open(LIVE_LOG) as f:
        for line in f:
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='ignore')
            if line.startswith('#'):
                continue
            p = line.strip().split('\t')
            if len(p) < 10:
                continue
            total_records += 1
            if p[6] != '-': tls[p[6]] += 1
            if p[8] != '-': curves[p[8]] += 1
            if p[9] != '-': snis[p[9]] += 1

    print(f"=== LIVE DATA QUALITY CHECK (CURRENT HOUR) ===")
    print(f"Total SSL/TLS Records this hour: {total_records:,}")

    if total_records > 0:
        print(f"\nTop TLS Versions:")
        for k, v in tls.most_common(4):
            print(f"  {k}: {v:,} ({v/total_records*100:.2f}%)")

        print(f"\nTop 10 SNIs (Destinations):")
        for k, v in snis.most_common(10):
            print(f"  {k}: {v:,}")

        print(f"\nTop Key Exchange Curves:")
        for k, v in curves.most_common(5):
            print(f"  {k}: {v:,} ({v/total_records*100:.2f}%)")

except Exception as e:
    print(f"Error reading live log: {e}")
