import os
import glob
import pandas as pd
import pyarrow.parquet as pq

BASE_DIR = r'F:\ARPA47-Dataset\zeek'
OUT_DIR = r'F:\ARPA47-Dataset\statistics'
os.makedirs(OUT_DIR, exist_ok=True)

print('Reading Parquet files to generate ground-truth CSVs...')

# conn
conn_stats = []
for f in glob.glob(os.path.join(BASE_DIR, 'conn', 'conn_*.parquet')):
    date_str = os.path.basename(f).split('_')[1].split('.')[0]
    df = pd.read_parquet(f, columns=['proto', 'orig_bytes', 'resp_bytes'])
    df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
    df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)
    
    conn_stats.append({
        'Date': date_str,
        'Total_Connections': len(df),
        'TCP': (df['proto'] == 'tcp').sum(),
        'UDP': (df['proto'] == 'udp').sum(),
        'ICMP': (df['proto'] == 'icmp').sum(),
        'Orig_Bytes': df['orig_bytes'].sum(),
        'Resp_Bytes': df['resp_bytes'].sum()
    })

if conn_stats:
    pd.DataFrame(conn_stats).sort_values('Date').to_csv(os.path.join(OUT_DIR, 'conn_daily_summary.csv'), index=False)

# ssl
ssl_stats = []
for f in glob.glob(os.path.join(BASE_DIR, 'ssl', 'ssl_*.parquet')):
    date_str = os.path.basename(f).split('_')[1].split('.')[0]
    df = pd.read_parquet(f, columns=['version', 'curve', 'server_name'])
    
    pqc_mask = df['curve'].astype(str).str.contains('kyber|mlkem', case=False, na=False)
    tls13_mask = df['version'] == 'TLSv13'
    
    ssl_stats.append({
        'Date': date_str,
        'Total_TLS_Connections': len(df),
        'TLS_1_2': (df['version'] == 'TLSv12').sum(),
        'TLS_1_3_no_PQC': (tls13_mask & ~pqc_mask).sum(),
        'PQC_Connections': pqc_mask.sum(),
        'Genuine_ECH': df['server_name'].astype(str).str.contains('ech', case=False, na=False).sum()
    })

if ssl_stats:
    pd.DataFrame(ssl_stats).sort_values('Date').to_csv(os.path.join(OUT_DIR, 'ssl_daily_summary.csv'), index=False)

# quic
quic_stats = []
for f in glob.glob(os.path.join(BASE_DIR, 'quic', 'quic_*.parquet')):
    date_str = os.path.basename(f).split('_')[1].split('.')[0]
    df = pd.read_parquet(f, columns=['server_name'])
    
    quic_stats.append({
        'Date': date_str,
        'Total_QUIC_Connections': len(df),
        'Hidden_SNI': df['server_name'].isna().sum() + (df['server_name'] == '-').sum()
    })

if quic_stats:
    pd.DataFrame(quic_stats).sort_values('Date').to_csv(os.path.join(OUT_DIR, 'quic_daily_summary.csv'), index=False)

# dns
dns_stats = []
for f in glob.glob(os.path.join(BASE_DIR, 'dns', 'dns_*.parquet')):
    date_str = os.path.basename(f).split('_')[1].split('.')[0]
    df = pd.read_parquet(f, columns=['qtype_name'])
    
    dns_stats.append({
        'Date': date_str,
        'Total_DNS_Queries': len(df),
        'A_Queries': (df['qtype_name'] == 'A').sum(),
        'AAAA_Queries': (df['qtype_name'] == 'AAAA').sum(),
        'HTTPS_Queries': (df['qtype_name'] == 'HTTPS').sum(),
        'Other_Queries': (~df['qtype_name'].isin(['A', 'AAAA', 'HTTPS'])).sum()
    })

if dns_stats:
    pd.DataFrame(dns_stats).sort_values('Date').to_csv(os.path.join(OUT_DIR, 'dns_daily_summary.csv'), index=False)

print('Success! Daily statistics written from Parquet.')
