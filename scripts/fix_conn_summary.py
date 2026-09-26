import os
import glob
import pandas as pd

DATASET_DIR = r"F:\ARPA47-Dataset\zeek"
STATS_DIR = r"F:\ARPA47-Dataset\statistics"

print("=== REGENERATING CONN SUMMARY WITH PROPER TCP/UDP SPLIT ===")

conn_files = sorted(glob.glob(os.path.join(DATASET_DIR, "conn", "*.parquet")))
conn_stats = []

for f in conn_files:
    date_str = os.path.basename(f).replace("conn_", "").replace(".parquet", "")
    try:
        # Read with explicit dtypes — all were written as strings in patched files
        df = pd.read_parquet(f, columns=['proto', 'orig_bytes', 'resp_bytes', 'service'])
        
        # Force numeric conversion since patched files may have string values
        df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
        df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)
        df['proto'] = df['proto'].astype(str).str.strip().str.lower()
        
        total = len(df)
        tcp = len(df[df['proto'] == 'tcp'])
        udp = len(df[df['proto'] == 'udp'])
        tls_service = len(df[df['service'].astype(str).str.lower() == 'ssl'])
        total_bytes = df['orig_bytes'].sum() + df['resp_bytes'].sum()
        total_gb = total_bytes / (1024**3)
        
        conn_stats.append({
            'Date': date_str,
            'Total_Connections': total,
            'TCP_Conns': tcp,
            'UDP_Conns': udp,
            'TCP_Pct': round(tcp/total*100, 1) if total > 0 else 0,
            'UDP_Pct': round(udp/total*100, 1) if total > 0 else 0,
            'TLS_Flows': tls_service,
            'Total_Traffic_GB': round(total_gb, 2)
        })
        print(f"  {date_str}: {total:>9,} flows  TCP={tcp:>8,} ({tcp/total*100:.1f}%)  UDP={udp:>8,} ({udp/total*100:.1f}%)  {total_gb:.1f} GB")
    except Exception as e:
        print(f"  ERROR on {date_str}: {e}")

summary_df = pd.DataFrame(conn_stats)
summary_df.to_csv(os.path.join(STATS_DIR, "conn_daily_summary.csv"), index=False)

print(f"\n=== TOTALS ===")
print(f"  Total connections : {summary_df['Total_Connections'].sum():,}")
print(f"  Total TCP         : {summary_df['TCP_Conns'].sum():,} ({summary_df['TCP_Conns'].sum()/summary_df['Total_Connections'].sum()*100:.1f}%)")
print(f"  Total UDP         : {summary_df['UDP_Conns'].sum():,} ({summary_df['UDP_Conns'].sum()/summary_df['Total_Connections'].sum()*100:.1f}%)")
print(f"  Total Traffic     : {summary_df['Total_Traffic_GB'].sum():.1f} GB")
print("\nDone! conn_daily_summary.csv updated.")
