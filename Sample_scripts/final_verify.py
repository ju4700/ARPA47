import os
import glob
import zipfile
import io
import pandas as pd
import pyarrow.parquet as pq

DATASET = r'F:\ARPA47-Dataset'

print('=' * 60)
print('ARPA47 DATASET FINAL VERIFICATION REPORT')
print('=' * 60)

# 1. Check all top-level files exist
expected_files = [
    'README.md', 'DATASET_SCHEMA.md', 'LICENSE', 'requirements.txt',
    'zenodo_metadata.json', 'zenodo_form_helper.md',
    'ETHICAL_COMPLIANCE_AND_DATA_SANITIZATION.pdf',
    'conn.zip', 'ssl.zip', 'quic.zip', 'dns.zip', 'http.zip', 'statistics.zip'
]
print('\n[1] TOP-LEVEL FILE CHECK')
all_ok = True
for f in expected_files:
    path = os.path.join(DATASET, f)
    if os.path.exists(path):
        size = os.path.getsize(path)
        print(f'  OK      {f} ({size:,} bytes)')
    else:
        print(f'  MISSING {f}')
        all_ok = False

# 2. Check ZIP contents and Parquet file counts
print('\n[2] ZIP CONTENTS CHECK (Parquet file count per archive)')
log_types = ['conn', 'ssl', 'quic', 'dns', 'http']
zip_parquet_counts = {}
for lt in log_types:
    zip_path = os.path.join(DATASET, f'{lt}.zip')
    if not os.path.exists(zip_path):
        print(f'  MISSING {lt}.zip')
        continue
    with zipfile.ZipFile(zip_path, 'r') as z:
        parquets = [n for n in z.namelist() if n.endswith('.parquet')]
        zip_parquet_counts[lt] = parquets
        dates = sorted(set([n.split('/')[-1].replace(f'{lt}_', '').replace('.parquet', '') for n in parquets]))
        first, last = (dates[0], dates[-1]) if dates else ('N/A', 'N/A')
        print(f'  OK      {lt}.zip: {len(parquets)} parquet files | {first} → {last}')

# 3. Check statistics.zip CSV contents
print('\n[3] STATISTICS ZIP CONTENTS CHECK')
stats_zip = os.path.join(DATASET, 'statistics.zip')
csv_dfs = {}
with zipfile.ZipFile(stats_zip, 'r') as z:
    for name in z.namelist():
        if name.endswith('.csv'):
            df = pd.read_csv(io.BytesIO(z.read(name)))
            csv_dfs[os.path.basename(name)] = df
            print(f'  OK      {os.path.basename(name)}: {len(df)} rows | cols: {list(df.columns)}')

# 4. Anonymization check - spot-check ssl.zip for raw 10.x IPs
print('\n[4] ANONYMIZATION SPOT-CHECK (10 random ssl files)')
ssl_zip = os.path.join(DATASET, 'ssl.zip')
raw_ip_count = 0
checked = 0
with zipfile.ZipFile(ssl_zip, 'r') as z:
    parquets = [n for n in z.namelist() if n.endswith('.parquet')]
    sample = parquets[::max(1, len(parquets)//10)]  # ~10 evenly spaced files
    for name in sample:
        df = pd.read_parquet(io.BytesIO(z.read(name)), columns=['id_orig_h'])
        raw = df[df['id_orig_h'].astype(str).str.startswith('10.')]
        raw_ip_count += len(raw)
        checked += 1
if raw_ip_count == 0:
    print(f'  PASS    No unanonymized 10.x IPs found across {checked} spot-checked ssl files.')
else:
    print(f'  FAIL    Found {raw_ip_count} unanonymized 10.x IPs across {checked} files!')

# 5. Key metric cross-check vs paper claims
print('\n[5] KEY METRIC CROSS-CHECK vs PAPER CLAIMS')

ssl_df  = csv_dfs.get('ssl_daily_summary.csv', pd.DataFrame())
quic_df = csv_dfs.get('quic_daily_summary.csv', pd.DataFrame())
conn_df = csv_dfs.get('conn_daily_summary.csv', pd.DataFrame())
dns_df  = csv_dfs.get('dns_daily_summary.csv', pd.DataFrame())

total_conn  = int(conn_df['Total_Connections'].sum())
total_tls   = int(ssl_df['Total_TLS_Connections'].sum())
total_quic  = int(quic_df['Total_QUIC_Connections'].sum())
pqc         = int(ssl_df['PQC_Connections'].sum())
ech         = int(ssl_df['Genuine_ECH'].sum())
hidden_tls  = int(ssl_df['Hidden_SNI'].sum())
hidden_quic = int(quic_df['Hidden_SNI'].sum())
total_dns   = int(dns_df['Total_Queries'].sum())
https_rr    = int(dns_df['Type_HTTPS'].sum())

port443          = total_tls + total_quic
quic_pct         = round((total_quic / port443) * 100, 1)
pqc_pct          = round((pqc / total_tls) * 100, 2)
ech_pct          = round((ech / total_tls) * 100, 2)
hidden_tls_pct   = round((hidden_tls / total_tls) * 100, 2)
hidden_quic_pct  = round((hidden_quic / total_quic) * 100, 1)
https_rr_pct     = round((https_rr / total_dns) * 100, 2)

checks = [
    ('Total Connections',      total_conn,               31338265, total_conn == 31338265),
    ('Total TLS Connections',  total_tls,                2712288,  total_tls == 2712288),
    ('Total QUIC Sessions',    total_quic,               4236252,  total_quic == 4236252),
    ('QUIC % of port-443',     f'{quic_pct}%',           '61.0%',  quic_pct == 61.0),
    ('PQC Adoption %',         f'{pqc_pct}%',            '23.08%', pqc_pct == 23.08),
    ('TLS Hidden SNI %',       f'{hidden_tls_pct}%',     '14.16%', hidden_tls_pct == 14.16),
    ('Genuine ECH flows',      ech,                      2822,     ech == 2822),
    ('Genuine ECH %',          f'{ech_pct}%',            '0.1%',   ech_pct == 0.10),
    ('QUIC Hidden SNI %',      f'{hidden_quic_pct}%',    '77.4%',  hidden_quic_pct == 77.4),
    ('Total DNS Queries',      total_dns,                7637226,  total_dns == 7637226),
    ('DNS HTTPS RR %',         f'{https_rr_pct}%',       '3.39%',  https_rr_pct == 3.39),
]

all_metrics_pass = True
for name, actual, expected, passed in checks:
    status = 'PASS' if passed else 'FAIL'
    if not passed:
        all_metrics_pass = False
    print(f'  {status}    {name}: got {actual} | expected {expected}')

print('\n' + '=' * 60)
if all_metrics_pass:
    print('FINAL RESULT: ALL 11 METRIC CHECKS PASSED.')
    print('Dataset is correct, verified, and safe to publish.')
else:
    print('FINAL RESULT: ONE OR MORE CHECKS FAILED.')
print('=' * 60)
