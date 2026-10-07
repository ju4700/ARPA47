import os
import gzip
import csv
from collections import defaultdict

BASE_DIR = r'F:\ARPA47\zeek_archive'

daily_conn = defaultdict(lambda: {'tcp': 0, 'udp': 0, 'icmp': 0, 'orig_bytes': 0, 'resp_bytes': 0, 'total': 0})
daily_ssl = defaultdict(lambda: {'total': 0, 'tls12': 0, 'tls13': 0, 'tls13_pqc': 0, 'ech': 0})
daily_quic = defaultdict(lambda: {'total': 0, 'hidden_sni': 0})
daily_dns = defaultdict(lambda: {'total': 0, 'a': 0, 'aaaa': 0, 'https': 0, 'other': 0})

print('Parsing Zeek Archive by Day...')

for root, _, files in os.walk(BASE_DIR):
    folder_name = os.path.basename(root)
    if not '_' in folder_name: continue
    
    date_str_raw = folder_name.split('_')[0]
    if len(date_str_raw) != 8: continue
    date_str = f"{date_str_raw[:4]}-{date_str_raw[4:6]}-{date_str_raw[6:]}"

    for f in files:
        if not f.endswith('.log.gz'): continue
        filepath = os.path.join(root, f)

        try:
            if f.startswith('conn'):
                with gzip.open(filepath, 'rt', encoding='ascii', errors='replace') as infile:
                    for line in infile:
                        if line.startswith('#'): continue
                        parts = line.split('\t')
                        if len(parts) < 11: continue
                        
                        proto = parts[6]
                        orig_bytes = parts[9]
                        resp_bytes = parts[10]

                        daily_conn[date_str]['total'] += 1
                        if proto == 'tcp': daily_conn[date_str]['tcp'] += 1
                        elif proto == 'udp': daily_conn[date_str]['udp'] += 1
                        elif proto == 'icmp': daily_conn[date_str]['icmp'] += 1

                        if orig_bytes.isdigit(): daily_conn[date_str]['orig_bytes'] += int(orig_bytes)
                        if resp_bytes.isdigit(): daily_conn[date_str]['resp_bytes'] += int(resp_bytes)

            elif f.startswith('ssl'):
                with gzip.open(filepath, 'rt', encoding='ascii', errors='replace') as infile:
                    for line in infile:
                        if line.startswith('#'): continue
                        parts = line.split('\t')
                        if len(parts) < 10: continue

                        version = parts[6]
                        curve = parts[13] if len(parts) > 13 else '-'
                        server_name = parts[9] if len(parts) > 9 else '-'

                        daily_ssl[date_str]['total'] += 1
                        if version == 'TLSv12': daily_ssl[date_str]['tls12'] += 1
                        elif version == 'TLSv13':
                            daily_ssl[date_str]['tls13'] += 1
                            if curve == 'X25519MLKEM768':
                                daily_ssl[date_str]['tls13_pqc'] += 1
                        
                        if server_name != '-' and 'cloudflare-ech.com' in server_name:
                            daily_ssl[date_str]['ech'] += 1

            elif f.startswith('quic'):
                with gzip.open(filepath, 'rt', encoding='ascii', errors='replace') as infile:
                    for line in infile:
                        if line.startswith('#'): continue
                        parts = line.split('\t')
                        if len(parts) < 10: continue

                        server_name = parts[7]
                        daily_quic[date_str]['total'] += 1
                        if server_name == '-':
                            daily_quic[date_str]['hidden_sni'] += 1

            elif f.startswith('dns'):
                with gzip.open(filepath, 'rt', encoding='ascii', errors='replace') as infile:
                    for line in infile:
                        if line.startswith('#'): continue
                        parts = line.split('\t')
                        if len(parts) < 16: continue

                        qtype = parts[14]
                        daily_dns[date_str]['total'] += 1
                        if qtype == '1': daily_dns[date_str]['a'] += 1
                        elif qtype == '28': daily_dns[date_str]['aaaa'] += 1
                        elif qtype == '65': daily_dns[date_str]['https'] += 1
                        else: daily_dns[date_str]['other'] += 1
        except EOFError:
            pass
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

print('Done parsing! Writing CSVs...')

out_dir = r'F:\ARPA47-Dataset\statistics'
os.makedirs(out_dir, exist_ok=True)

with open(os.path.join(out_dir, 'conn_daily_summary.csv'), 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Date', 'Total_Conns', 'TCP_Conns', 'UDP_Conns', 'ICMP_Conns', 'Orig_Bytes', 'Resp_Bytes'])
    for d in sorted(daily_conn.keys()):
        s = daily_conn[d]
        writer.writerow([d, s['total'], s['tcp'], s['udp'], s['icmp'], s['orig_bytes'], s['resp_bytes']])

with open(os.path.join(out_dir, 'ssl_daily_summary.csv'), 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Date', 'Total_TLS_Connections', 'TLS_1_2', 'TLS_1_3_no_PQC', 'PQC_Connections', 'Genuine_ECH'])
    for d in sorted(daily_ssl.keys()):
        s = daily_ssl[d]
        tls13_nopqc = s['tls13'] - s['tls13_pqc']
        writer.writerow([d, s['total'], s['tls12'], tls13_nopqc, s['tls13_pqc'], s['ech']])

with open(os.path.join(out_dir, 'quic_daily_summary.csv'), 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Date', 'Total_QUIC', 'Hidden_SNI'])
    for d in sorted(daily_quic.keys()):
        s = daily_quic[d]
        writer.writerow([d, s['total'], s['hidden_sni']])

with open(os.path.join(out_dir, 'dns_daily_summary.csv'), 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Date', 'Total_Queries', 'A_Records', 'AAAA_Records', 'HTTPS_Records', 'Other_Records'])
    for d in sorted(daily_dns.keys()):
        s = daily_dns[d]
        writer.writerow([d, s['total'], s['a'], s['aaaa'], s['https'], s['other']])

print('Success! Daily statistics written.')
