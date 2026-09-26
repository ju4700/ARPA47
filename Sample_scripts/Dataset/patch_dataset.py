import os
import glob
import gzip
import hmac
import hashlib
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from datetime import datetime
from collections import defaultdict

INPUT_DIR = r"F:\ARPA47\zeek_archive"
OUTPUT_DIR = r"F:\ARPA47-Dataset\zeek"
LOG_TYPES = ["ssl", "conn", "dns", "quic", "http"]

# Use a fixed key for the patch so anonymization stays consistent 
# (In a real run we'd save/load this, but we'll use a static one for the patch)
SECRET_KEY = b'arpa47_patch_key_1234567890123456'

def anonymize_ip(ip):
    if isinstance(ip, str) and ip.startswith("10.60.1."):
        digest = hmac.new(SECRET_KEY, ip.encode(), hashlib.sha256).hexdigest()[:8]
        return f"sub_{digest}"
    return ip

def get_schema(log_type):
    # Find any file of this type that HAS a header to extract the true schema
    for folder in glob.glob(os.path.join(INPUT_DIR, "*_*")):
        files = glob.glob(os.path.join(folder, f"{log_type}_*.log.gz"))
        if not files: continue
        try:
            with gzip.open(files[0], 'rt', encoding='ascii', errors='replace') as f:
                for line in f:
                    if line.startswith("#fields"):
                        return line.strip().split('\t')[1:]
        except Exception:
            continue
    return None

schemas = {}
for lt in LOG_TYPES:
    schemas[lt] = get_schema(lt)
    print(f"Schema for {lt} found: {len(schemas[lt]) if schemas[lt] else 'NONE'} columns")

# Map of day folders
all_folders = glob.glob(os.path.join(INPUT_DIR, "*_*"))
date_to_folders = defaultdict(list)
for folder in sorted(all_folders):
    basename = os.path.basename(folder)
    if "_" in basename:
        date_part = basename.split("_")[0]
        if len(date_part) == 8:
            formatted_date = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:]}"
            date_to_folders[formatted_date].append(folder)

def process_day(date_str, folder_paths):
    print(f"\nChecking missing files for {date_str}...")
    
    for log_type in LOG_TYPES:
        output_file = os.path.join(OUTPUT_DIR, log_type, f"{log_type}_{date_str}.parquet")
        if os.path.exists(output_file):
            continue # Already processed
            
        print(f"  -> Patching missing file: {log_type}_{date_str}.parquet")
        columns = schemas[log_type]
        if not columns:
            print(f"     No schema found for {log_type}, skipping.")
            continue
            
        dfs = []
        for folder in folder_paths:
            search_pattern = os.path.join(folder, f"{log_type}_*.log.gz")
            files = glob.glob(search_pattern)
            if not files: continue
            
            try:
                # Force all columns to string to prevent PyArrow type mixup crashes
                df = pd.read_csv(
                    files[0], sep='\t', comment='#', names=columns, 
                    dtype=str, low_memory=False, on_bad_lines='skip'
                )
                if not df.empty:
                    dfs.append(df)
            except Exception as e:
                pass
                
        if not dfs:
            print("     No valid data found for this day.")
            continue
            
        combined_df = pd.concat(dfs, ignore_index=True)
        
        # Anonymize
        if 'id.orig_h' in combined_df.columns:
            combined_df['id.orig_h'] = combined_df['id.orig_h'].apply(anonymize_ip)
            
        # Convert timestamp
        if 'ts' in combined_df.columns:
            combined_df['ts'] = pd.to_numeric(combined_df['ts'], errors='coerce')
            combined_df['ts'] = pd.to_datetime(combined_df['ts'], unit='s', errors='coerce')
            
        # Write Parquet
        try:
            table = pa.Table.from_pandas(combined_df)
            pq.write_table(table, output_file, compression='snappy')
            print(f"     [SUCCESS] Wrote patched {log_type}_{date_str}.parquet ({len(combined_df)} records)")
        except Exception as e:
            print(f"     [FAILED] Could not write Parquet: {e}")

for date_str in sorted(date_to_folders.keys()):
    process_day(date_str, date_to_folders[date_str])

print("\nPatch Complete!")
