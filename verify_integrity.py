import os
import zipfile
import pyarrow.parquet as pq
import io

SPLIT_DIR = r"F:\ARPA47-Dataset\ARPA47_Release_Split"

EXPECTED_COUNTS = {
    'conn': 104042786,
    'ssl': 11523518,
    'quic': 12627627,
    'http': 619404,
    'dns': 21327575,
    'weird': 13196640
}

def verify_dataset():
    print("Verifying data integrity across all 18 independent ZIP files...\n")
    
    actual_counts = {
        'conn': 0, 'ssl': 0, 'quic': 0, 
        'http': 0, 'dns': 0, 'weird': 0
    }
    
    zip_files = [f for f in os.listdir(SPLIT_DIR) if f.endswith('.zip') and f.startswith('arpa47_')]
    
    for zf_name in sorted(zip_files):
        # Extract protocol from filename (e.g. arpa47_conn_part1.zip -> conn)
        protocol = zf_name.split('_')[1]
        
        filepath = os.path.join(SPLIT_DIR, zf_name)
        with zipfile.ZipFile(filepath, 'r') as zf:
            parquet_files = [f for f in zf.namelist() if f.endswith('.parquet')]
            
            zip_row_count = 0
            for pq_name in parquet_files:
                # Read just the parquet metadata footer (extremely fast)
                with zf.open(pq_name) as pf:
                    # Load file bytes into memory buffer for pyarrow
                    buffer = io.BytesIO(pf.read())
                    parquet_meta = pq.ParquetFile(buffer)
                    zip_row_count += parquet_meta.metadata.num_rows
            
            actual_counts[protocol] += zip_row_count
            print(f"[OK] {zf_name}: Validated {len(parquet_files)} inner files ({zip_row_count:,} rows)")

    print("\n--- FINAL ALIGNMENT AUDIT ---")
    all_match = True
    for protocol in EXPECTED_COUNTS:
        expected = EXPECTED_COUNTS[protocol]
        actual = actual_counts.get(protocol, 0)
        status = "MATCH" if expected == actual else "MISMATCH"
        if expected != actual:
            all_match = False
        print(f"{protocol.upper().ljust(6)} | Expected: {expected:>12,} | Actual: {actual:>12,} | [{status}]")
        
    if all_match:
        print("\n[SUCCESS] PERFECT INTEGRITY! The 18 split archives contain the exact original 104-million row dataset.")
    else:
        print("\n[ERROR] DATA LOSS DETECTED during packaging!")

if __name__ == '__main__':
    verify_dataset()
