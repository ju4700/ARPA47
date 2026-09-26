import os
import glob
import gzip
import hmac
import hashlib
import secrets
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from datetime import datetime
from collections import defaultdict

# Setup
INPUT_DIR = r"F:\ARPA47\zeek_archive"
OUTPUT_DIR = r"F:\ARPA47-Dataset\zeek"
LOG_TYPES = ["ssl", "conn", "dns", "quic", "http"]
SECRET_KEY = secrets.token_bytes(32)

print(f"Starting Dataset Build: {INPUT_DIR} -> {OUTPUT_DIR}")

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

for log_type in LOG_TYPES:
    ensure_dir(os.path.join(OUTPUT_DIR, log_type))
ensure_dir(os.path.join(OUTPUT_DIR, "../statistics"))

def anonymize_ip(ip):
    if isinstance(ip, str) and ip.startswith("10.60.1."):
        digest = hmac.new(SECRET_KEY, ip.encode(), hashlib.sha256).hexdigest()[:8]
        return f"sub_{digest}"
    return ip

def process_day(date_str, folder_paths):
    print(f"\nProcessing {date_str} ({len(folder_paths)} hours)")
    
    for log_type in LOG_TYPES:
        output_file = os.path.join(OUTPUT_DIR, log_type, f"{log_type}_{date_str}.parquet")
        if os.path.exists(output_file):
            print(f"  Skipping {log_type} (already exists)")
            continue
            
        dfs = []
        for folder in folder_paths:
            # Find the log file in this folder
            search_pattern = os.path.join(folder, f"{log_type}_*.log.gz")
            files = glob.glob(search_pattern)
            if not files:
                continue
                
            file_path = files[0]
            
            # Read header to get column names
            columns = []
            try:
                with gzip.open(file_path, 'rt', encoding='ascii', errors='replace') as f:
                    for line in f:
                        if line.startswith("#fields"):
                            columns = line.strip().split('\t')[1:]
                            break
            except Exception as e:
                print(f"  Error reading header from {file_path}: {e}")
                continue
                
            if not columns:
                continue
                
            # Read data
            try:
                df = pd.read_csv(file_path, sep='\t', comment='#', names=columns, low_memory=False, on_bad_lines='skip')
                if not df.empty:
                    dfs.append(df)
            except Exception as e:
                print(f"  Error parsing {file_path}: {e}")
                
        if not dfs:
            continue
            
        # Combine all hours for this log type for this day
        combined_df = pd.concat(dfs, ignore_index=True)
        
        # Anonymize
        if 'id.orig_h' in combined_df.columns:
            combined_df['id.orig_h'] = combined_df['id.orig_h'].apply(anonymize_ip)
            
        # Convert timestamp to datetime if 'ts' exists
        if 'ts' in combined_df.columns:
            combined_df['ts'] = pd.to_datetime(combined_df['ts'], unit='s', errors='coerce')
            
        # Write to Parquet
        try:
            table = pa.Table.from_pandas(combined_df)
            pq.write_table(table, output_file, compression='snappy')
            print(f"  -> Wrote {log_type}_{date_str}.parquet ({len(combined_df)} records)")
        except Exception as e:
            print(f"  Error writing Parquet for {log_type}: {e}")

# Gather folders
print("Scanning folders...")
all_folders = glob.glob(os.path.join(INPUT_DIR, "*_*"))
date_to_folders = defaultdict(list)

for folder in sorted(all_folders):
    basename = os.path.basename(folder)
    if "_" in basename:
        # e.g., 20260826_19
        date_part = basename.split("_")[0]
        if len(date_part) == 8:
            formatted_date = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:]}"
            date_to_folders[formatted_date].append(folder)

print(f"Found {len(date_to_folders)} unique days to process.")

# Process each day
for date_str in sorted(date_to_folders.keys()):
    process_day(date_str, date_to_folders[date_str])

print("\nDataset Build Complete!")
