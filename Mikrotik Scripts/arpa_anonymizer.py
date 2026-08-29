import os
import sys
import hashlib
import subprocess
import glob
import pandas as pd
from datetime import datetime

# Configuration
SALT = os.environ.get("ARPA_ANONYMIZATION_SALT", "default_secret_salt_2026")
DATA_DIR = "/data/arpa"
ZEEK_DIR = os.path.join(DATA_DIR, "zeek_logs")
NETFLOW_DIR = os.path.join(DATA_DIR, "netflow")
PARQUET_DIR = os.path.join(DATA_DIR, "parquet")

# Ensure output directory exists
os.makedirs(PARQUET_DIR, exist_ok=True)

def anonymize_ip(ip_str):
    if not ip_str or not isinstance(ip_str, str) or ip_str == '-':
        return '-'
    # SHA-256 hash of (salt + IP)
    h = hashlib.sha256((SALT + ip_str).encode('utf-8')).hexdigest()
    return f"Anon_{h[:12]}"

def process_zeek_logs():
    print("Processing Zeek ssl logs...")
    ssl_files = glob.glob(os.path.join(ZEEK_DIR, "ssl*.log"))
    if not ssl_files:
        print("No ssl logs found.")
        return

    for ssl_file in ssl_files:
        print(f"Processing {ssl_file}...")
        try:
            with open(ssl_file, 'r') as f:
                lines = f.readlines()
            
            headers = None
            for line in lines:
                if line.startswith("#fields"):
                    headers = line.strip().split('\t')[1:]
                    break
                    
            if not headers:
                print(f"Could not find headers in {ssl_file}")
                continue

            # Load into Pandas, skipping comments
            df = pd.read_csv(ssl_file, sep='\t', comment='#', names=headers)
            
            # Anonymize IPs
            if 'id.orig_h' in df.columns:
                df['id.orig_h'] = df['id.orig_h'].apply(anonymize_ip)
            if 'id.resp_h' in df.columns:
                df['id.resp_h'] = df['id.resp_h'].apply(anonymize_ip)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            basename = os.path.basename(ssl_file).replace('.log', '')
            out_file = os.path.join(PARQUET_DIR, f"zeek_{basename}_{timestamp}.parquet")
            df.to_parquet(out_file, engine='pyarrow', index=False)
            print(f"Saved anonymized Zeek SSL data to {out_file}")
            
            # Optionally remove the raw log after processing:
            # os.remove(ssl_file)
            
        except Exception as e:
            print(f"Error processing {ssl_file}: {e}")

def process_netflow():
    print("Processing NetFlow (nfcapd) files...")
    # Find all nfcapd files not yet processed (ignoring the current one usually ending in .current)
    files = glob.glob(os.path.join(NETFLOW_DIR, "nfcapd.20*"))
    if not files:
        print("No nfcapd files found.")
        return

    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_tmp = f"/tmp/netflow_{timestamp}.csv"
        
        # Use nfdump to convert binary nfcapd files to CSV
        cmd = f"nfdump -R {NETFLOW_DIR} -o csv > {csv_tmp}"
        subprocess.run(cmd, shell=True, check=True)
        
        # Read CSV into pandas (nfdump CSV output has summary rows at the end, so skip them)
        df = pd.read_csv(csv_tmp, skipfooter=3, engine='python', on_bad_lines='skip')
        
        if 'sa' in df.columns:
            df['sa'] = df['sa'].apply(anonymize_ip)
        if 'da' in df.columns:
            df['da'] = df['da'].apply(anonymize_ip)
            
        out_file = os.path.join(PARQUET_DIR, f"netflow_{timestamp}.parquet")
        df.to_parquet(out_file, engine='pyarrow', index=False)
        print(f"Saved anonymized NetFlow data to {out_file}")
        
        # Clean up tmp csv
        os.remove(csv_tmp)
        
    except Exception as e:
        print(f"Error processing NetFlow logs: {e}")

if __name__ == "__main__":
    print(f"Starting ARPA Anonymization Pipeline at {datetime.now()}")
    process_zeek_logs()
    process_netflow()
    print("Pipeline finished.")
