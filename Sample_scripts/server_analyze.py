import collections
import gzip
import os
import glob
import sys

ARCHIVE_DIR = '/data/arpa/zeek_archive'
LIVE_LOG = '/data/arpa/zeek_logs/ssl.log'

tls = collections.Counter()
curves = collections.Counter()
snis = collections.Counter()
total_records = 0
files_processed = 0

def process_lines(f):
    global total_records, files_processed
    n = 0
    for line in f:
        if isinstance(line, bytes):
            line = line.decode('utf-8', errors='ignore')
        if line.startswith('#'):
            continue
        p = line.strip().split('\t')
        if len(p) < 10:
            continue
        n += 1
        if p[6] != '-': tls[p[6]] += 1
        if p[8] != '-': curves[p[8]] += 1
        if p[9] != '-': snis[p[9]] += 1
    return n

# Process archived gz files (pattern: ssl_YYYYMMDD_HHMMSS.log.gz)
ssl_gz_files = sorted(glob.glob(os.path.join(ARCHIVE_DIR, '**', 'ssl_*.log.gz'), recursive=True))
print(f"Found {len(ssl_gz_files)} archived ssl.log.gz files...", flush=True)

for fpath in ssl_gz_files:
    try:
        with gzip.open(fpath, 'rb') as f:
            n = process_lines(f)
            total_records += n
            files_processed += 1
    except Exception as e:
        print(f"  WARN: {fpath}: {e}", file=sys.stderr)

# Also add current live log
try:
    with open(LIVE_LOG) as f:
        n = process_lines(f)
        total_records += n
        files_processed += 1
    print(f"Added live ssl.log ({n:,} records)", flush=True)
except Exception as e:
    print(f"  WARN live log: {e}", file=sys.stderr)

print(f"\n=== 11-DAY AGGREGATE ZEEK SSL REPORT ===")
print(f"Files processed: {files_processed}")
print(f"Total SSL/TLS Records: {total_records:,}")

if total_records > 0:
    print(f"\nTLS Version Breakdown:")
    for k, v in tls.most_common(6):
        print(f"  {k}: {v:,} ({v/total_records*100:.2f}%)")

    blank_tls = total_records - sum(tls.values())
    print(f"  (blank/incomplete handshake): {blank_tls:,} ({blank_tls/total_records*100:.2f}%)")

    print(f"\nTop 15 SNIs (Destinations):")
    for k, v in snis.most_common(15):
        print(f"  {k}: {v:,}")

    print(f"\nKey Exchange Curves:")
    for k, v in curves.most_common(10):
        print(f"  {k}: {v:,} ({v/total_records*100:.2f}%)")
    blank_curves = total_records - sum(curves.values())
    print(f"  (blank/no curve): {blank_curves:,} ({blank_curves/total_records*100:.2f}%)")
