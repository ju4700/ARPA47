import os
import glob
import pandas as pd

DATASET_DIR = r"F:\ARPA47-Dataset\zeek"
STATS_DIR = r"F:\ARPA47-Dataset\statistics"

print("=" * 60)
print("ARPA47 COMPREHENSIVE PAPER STATISTICS")
print("=" * 60)

# ===== TLS/SSL STATS =====
print("\n[1] TLS/SSL HANDSHAKE BREAKDOWN")
ssl_files = sorted(glob.glob(os.path.join(DATASET_DIR, "ssl", "*.parquet")))
all_ssl = []
for f in ssl_files:
    df = pd.read_parquet(f, columns=['version', 'curve', 'sni' if 'sni' in pd.read_parquet(f, columns=None).columns else 'server_name'])
    all_ssl.append(df)

ssl_df = pd.concat(all_ssl, ignore_index=True)
# Rename server_name to sni if needed
if 'server_name' in ssl_df.columns and 'sni' not in ssl_df.columns:
    ssl_df = ssl_df.rename(columns={'server_name': 'sni'})

total_tls = len(ssl_df)
tls12 = len(ssl_df[~ssl_df['version'].astype(str).str.contains('TLSv13|TLSv1.3', na=False)])
tls13 = len(ssl_df[ssl_df['version'].astype(str).str.contains('TLSv13|TLSv1.3', na=False)])
pqc = len(ssl_df[ssl_df['curve'].astype(str).str.contains('MLKEM|kyber', case=False, na=False)])
tls13_no_pqc = tls13 - pqc

# ECH detection: SNI = cloudflare-ech.com = genuine ECH
sni_col = 'sni' if 'sni' in ssl_df.columns else None
if sni_col:
    genuine_ech = len(ssl_df[ssl_df[sni_col].astype(str).str.lower().str.contains('cloudflare-ech', na=False)])
    empty_sni = len(ssl_df[ssl_df[sni_col].astype(str).isin(['-', '', 'nan', 'None'])])
else:
    genuine_ech = 0
    empty_sni = 0

print(f"  Total TLS connections     : {total_tls:>10,}")
print(f"  TLS 1.2 (legacy)          : {tls12:>10,}  ({tls12/total_tls*100:.2f}%)")
print(f"  TLS 1.3 (no PQC)          : {tls13_no_pqc:>10,}  ({tls13_no_pqc/total_tls*100:.2f}%)")
print(f"  TLS 1.3 with PQC (MLKEM)  : {pqc:>10,}  ({pqc/total_tls*100:.2f}%)")
print(f"  ALL TLS 1.3               : {tls13:>10,}  ({tls13/total_tls*100:.2f}%)")
print(f"  Genuine ECH (cloudflare)  : {genuine_ech:>10,}  ({genuine_ech/total_tls*100:.4f}%)")
print(f"  Empty/Hidden SNI          : {empty_sni:>10,}  ({empty_sni/total_tls*100:.2f}%)")

# ===== QUIC STATS =====
print("\n[2] QUIC (HTTP/3) BREAKDOWN")
quic_files = sorted(glob.glob(os.path.join(DATASET_DIR, "quic", "*.parquet")))
all_quic = []
for f in quic_files:
    df = pd.read_parquet(f)
    all_quic.append(df)

quic_df = pd.concat(all_quic, ignore_index=True)
total_quic = len(quic_df)

# QUIC version breakdown
quic_versions = quic_df['version'].astype(str).value_counts().head(5)
print(f"  Total QUIC connections    : {total_quic:>10,}")
print(f"  QUIC version breakdown:")
for ver, cnt in quic_versions.items():
    print(f"    {ver:<30}: {cnt:>8,}  ({cnt/total_quic*100:.1f}%)")

# QUIC SNI
if 'server_name' in quic_df.columns:
    quic_hidden_sni = len(quic_df[quic_df['server_name'].astype(str).isin(['-', '', 'nan'])])
    print(f"  QUIC with hidden SNI      : {quic_hidden_sni:>10,}  ({quic_hidden_sni/total_quic*100:.1f}%)")

# ===== DNS STATS =====
print("\n[3] DNS QUERY BREAKDOWN")
dns_files = sorted(glob.glob(os.path.join(DATASET_DIR, "dns", "*.parquet")))
all_dns = []
for f in dns_files:
    try:
        df = pd.read_parquet(f, columns=['qtype_name'] if 'qtype_name' in pd.read_parquet(f, columns=None).columns else None)
        all_dns.append(df)
    except:
        df = pd.read_parquet(f)
        all_dns.append(df)

dns_df = pd.concat(all_dns, ignore_index=True)
total_dns = len(dns_df)
print(f"  Total DNS queries         : {total_dns:>10,}")

if 'qtype_name' in dns_df.columns:
    qtypes = dns_df['qtype_name'].astype(str).value_counts().head(8)
    print(f"  Query type breakdown:")
    https_queries = 0
    for qt, cnt in qtypes.items():
        pct = cnt/total_dns*100
        print(f"    {qt:<10}: {cnt:>9,}  ({pct:.2f}%)")
        if qt.upper() in ['HTTPS', '65']:
            https_queries = cnt
    print(f"  HTTPS RR queries          : {https_queries:>10,}  ({https_queries/total_dns*100:.2f}%)")

# ===== OVERALL CONN STATS =====
print("\n[4] OVERALL CONNECTION STATISTICS (from good days only)")
conn_summary = pd.read_csv(os.path.join(STATS_DIR, "conn_daily_summary.csv"))
good_days = conn_summary[conn_summary['TCP_Conns'] > 0]
all_days = conn_summary

print(f"  Total days collected      : {len(all_days)}")
print(f"  Days with full TCP/UDP    : {len(good_days)}")
print(f"  Total connections (all)   : {all_days['Total_Connections'].sum():>10,}")
print(f"  Total traffic (all)       : {all_days['Total_Traffic_GB'].sum():>10.1f} GB")
print(f"  --- From {len(good_days)} fully-classified days: ---")
if len(good_days) > 0:
    g_total = good_days['Total_Connections'].sum()
    g_tcp = good_days['TCP_Conns'].sum()
    g_udp = good_days['UDP_Conns'].sum()
    print(f"  TCP connections           : {g_tcp:>10,}  ({g_tcp/g_total*100:.1f}%)")
    print(f"  UDP connections           : {g_udp:>10,}  ({g_udp/g_total*100:.1f}%)")
    print(f"  Other (ICMP, etc.)        : {g_total-g_tcp-g_udp:>10,}  ({(g_total-g_tcp-g_udp)/g_total*100:.1f}%)")

print("\n" + "="*60)
print("SUMMARY FOR PAPER:")
print("="*60)
print(f"  Collection window : Aug 26 – Sep 26, 2026 (31 days)")
print(f"  Total TLS flows   : {total_tls:,}")
print(f"  TLS 1.2 rate      : {tls12/total_tls*100:.1f}%")
print(f"  TLS 1.3 rate      : {tls13/total_tls*100:.1f}%")
print(f"  PQC adoption      : {pqc/total_tls*100:.2f}%")
print(f"  ECH (genuine)     : {genuine_ech:,} flows ({genuine_ech/total_tls*100:.4f}%)")
print(f"  QUIC total        : {total_quic:,}")
print(f"  Total DNS queries : {total_dns:,}")
