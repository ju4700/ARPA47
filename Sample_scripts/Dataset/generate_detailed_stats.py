import os
import glob
import pandas as pd
import numpy as np

DATASET_DIR = r"F:\ARPA47-Dataset\zeek"
STATS_DIR = r"F:\ARPA47-Dataset\statistics"
os.makedirs(STATS_DIR, exist_ok=True)

print("Generating detailed daily statistics...")

# 1. SSL/TLS Summary
print("Processing SSL...")
ssl_files = sorted(glob.glob(os.path.join(DATASET_DIR, "ssl", "*.parquet")))
ssl_stats = []
for f in ssl_files:
    date_str = os.path.basename(f).replace("ssl_", "").replace(".parquet", "")
    df = pd.read_parquet(f)
    
    total = len(df)
    tls12 = len(df[~df['version'].astype(str).str.contains('TLSv13|TLSv1.3', na=False)])
    tls13 = len(df[df['version'].astype(str).str.contains('TLSv13|TLSv1.3', na=False)])
    pqc = len(df[df['curve'].astype(str).str.contains('MLKEM|kyber', case=False, na=False)])
    tls13_no_pqc = tls13 - pqc
    
    sni_col = 'sni' if 'sni' in df.columns else 'server_name'
    if sni_col in df.columns:
        genuine_ech = len(df[df[sni_col].astype(str).str.lower().str.contains('cloudflare-ech', na=False)])
        hidden_sni = len(df[df[sni_col].astype(str).isin(['-', '', 'nan', 'None'])])
    else:
        genuine_ech = 0
        hidden_sni = 0
        
    ssl_stats.append({
        'Date': date_str,
        'Total_TLS_Connections': total,
        'TLS_1_2': tls12,
        'TLS_1_3_no_PQC': tls13_no_pqc,
        'PQC_Connections': pqc,
        'Genuine_ECH': genuine_ech,
        'Hidden_SNI': hidden_sni
    })
pd.DataFrame(ssl_stats).to_csv(os.path.join(STATS_DIR, "ssl_daily_summary.csv"), index=False)

# 2. QUIC Summary
print("Processing QUIC...")
quic_files = sorted(glob.glob(os.path.join(DATASET_DIR, "quic", "*.parquet")))
quic_stats = []
for f in quic_files:
    date_str = os.path.basename(f).replace("quic_", "").replace(".parquet", "")
    df = pd.read_parquet(f)
    total = len(df)
    if 'server_name' in df.columns:
        hidden_sni = len(df[df['server_name'].astype(str).isin(['-', '', 'nan', 'None'])])
    else:
        hidden_sni = 0
        
    quic_stats.append({
        'Date': date_str,
        'Total_QUIC_Connections': total,
        'Hidden_SNI': hidden_sni
    })
pd.DataFrame(quic_stats).to_csv(os.path.join(STATS_DIR, "quic_daily_summary.csv"), index=False)

# 3. DNS Summary
print("Processing DNS...")
dns_files = sorted(glob.glob(os.path.join(DATASET_DIR, "dns", "*.parquet")))
dns_stats = []
for f in dns_files:
    date_str = os.path.basename(f).replace("dns_", "").replace(".parquet", "")
    try:
        df = pd.read_parquet(f, columns=['qtype_name'] if 'qtype_name' in pd.read_parquet(f, columns=None).columns else None)
    except:
        df = pd.read_parquet(f)
        
    total = len(df)
    if 'qtype_name' in df.columns:
        qtypes = df['qtype_name'].astype(str).str.upper()
        type_a = len(qtypes[qtypes == 'A'])
        type_aaaa = len(qtypes[qtypes == 'AAAA'])
        type_https = len(qtypes[qtypes.isin(['HTTPS', '65'])])
    else:
        type_a = 0; type_aaaa = 0; type_https = 0
        
    dns_stats.append({
        'Date': date_str,
        'Total_Queries': total,
        'Type_A': type_a,
        'Type_AAAA': type_aaaa,
        'Type_HTTPS': type_https,
        'Type_Other': total - (type_a + type_aaaa + type_https)
    })
pd.DataFrame(dns_stats).to_csv(os.path.join(STATS_DIR, "dns_daily_summary.csv"), index=False)

print("Detailed statistics generated successfully!")
