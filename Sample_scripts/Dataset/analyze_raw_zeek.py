import os
import gzip
import csv
from collections import Counter
from multiprocessing import Pool
from tqdm import tqdm

ARCHIVE_DIR = r"F:\ARPA47\zeek_archive"

def analyze_hour(folder_path):
    stats = {
        'total_conn': 0,
        'total_ssl': 0,
        'total_quic': 0,
        'total_dns': 0,
        'total_http': 0,
        'total_weird': 0,
        
        'tls_versions': Counter(),
        'tls_curves': Counter(),
        'ech_cloudflare': 0,
        
        'quic_versions': Counter(),
        'quic_missing_sni': 0,
        
        'dns_qtypes': Counter(),
        
        'weird_names': Counter(),
    }
    
    for file in os.listdir(folder_path):
        if not file.endswith(".log.gz"):
            continue
            
        file_path = os.path.join(folder_path, file)
        
        # 1. conn.log
        if file.startswith("conn"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if not line.startswith('#'):
                            stats['total_conn'] += 1
            except Exception:
                pass

        # 2. ssl.log
        elif file.startswith("ssl"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 9:
                            stats['total_ssl'] += 1
                            version = row[6]
                            curve = row[8]
                            server_name = row[9]
                            
                            if version != '-':
                                stats['tls_versions'][version] += 1
                            if curve != '-':
                                stats['tls_curves'][curve] += 1
                            if 'cloudflare-ech.com' in server_name:
                                stats['ech_cloudflare'] += 1
            except Exception:
                pass

        # 3. quic.log
        elif file.startswith("quic"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 10:
                            stats['total_quic'] += 1
                            version = row[6]
                            server_name = row[10]
                            
                            if version != '-':
                                stats['quic_versions'][version] += 1
                            if server_name == '-':
                                stats['quic_missing_sni'] += 1
            except Exception:
                pass
                
        # 4. dns.log
        elif file.startswith("dns"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 13:
                            stats['total_dns'] += 1
                            qtype = row[13] # qtype_name
                            if qtype != '-':
                                stats['dns_qtypes'][qtype] += 1
            except Exception:
                pass

        # 5. weird.log
        elif file.startswith("weird"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 6:
                            stats['total_weird'] += 1
                            name = row[6]
                            stats['weird_names'][name] += 1
            except Exception:
                pass

    return stats

def main():
    folders = [os.path.join(ARCHIVE_DIR, d) for d in os.listdir(ARCHIVE_DIR) if os.path.isdir(os.path.join(ARCHIVE_DIR, d))]
    print(f"Found {len(folders)} hourly folders to analyze in {ARCHIVE_DIR}")
    
    global_stats = {
        'total_conn': 0, 'total_ssl': 0, 'total_quic': 0, 'total_dns': 0, 'total_http': 0, 'total_weird': 0,
        'tls_versions': Counter(), 'tls_curves': Counter(), 'ech_cloudflare': 0,
        'quic_versions': Counter(), 'quic_missing_sni': 0,
        'dns_qtypes': Counter(), 'weird_names': Counter()
    }
    
    with Pool(os.cpu_count()) as pool:
        results = list(tqdm(pool.imap_unordered(analyze_hour, folders), total=len(folders)))
        
    for r in results:
        global_stats['total_conn'] += r['total_conn']
        global_stats['total_ssl'] += r['total_ssl']
        global_stats['total_quic'] += r['total_quic']
        global_stats['total_dns'] += r['total_dns']
        global_stats['total_weird'] += r['total_weird']
        global_stats['ech_cloudflare'] += r['ech_cloudflare']
        global_stats['quic_missing_sni'] += r['quic_missing_sni']
        
        global_stats['tls_versions'].update(r['tls_versions'])
        global_stats['tls_curves'].update(r['tls_curves'])
        global_stats['quic_versions'].update(r['quic_versions'])
        global_stats['dns_qtypes'].update(r['dns_qtypes'])
        global_stats['weird_names'].update(r['weird_names'])

    with open("raw_zeek_stats.txt", "w") as f:
        f.write("=== RAW ZEEK DATASET STATISTICS ===\n\n")
        f.write(f"Total Connections (conn.log) : {global_stats['total_conn']:,}\n")
        f.write(f"Total TLS Sessions (ssl.log) : {global_stats['total_ssl']:,}\n")
        f.write(f"Total QUIC Sessions          : {global_stats['total_quic']:,}\n")
        f.write(f"Total DNS Queries            : {global_stats['total_dns']:,}\n")
        f.write(f"Total Weird Events           : {global_stats['total_weird']:,}\n\n")
        
        f.write("--- TLS STATISTICS ---\n")
        for k, v in global_stats['tls_versions'].most_common():
            f.write(f"  {k}: {v:,}\n")
        f.write("\nTop TLS Curves:\n")
        for k, v in global_stats['tls_curves'].most_common(5):
            f.write(f"  {k}: {v:,}\n")
        f.write(f"\nGenuine ECH (cloudflare-ech.com): {global_stats['ech_cloudflare']:,}\n\n")
        
        f.write("--- QUIC STATISTICS ---\n")
        f.write(f"Missing SNI: {global_stats['quic_missing_sni']:,} / {global_stats['total_quic']:,}\n")
        for k, v in global_stats['quic_versions'].most_common(3):
            f.write(f"  {k}: {v:,}\n")
            
        f.write("\n--- DNS STATISTICS ---\n")
        for k, v in global_stats['dns_qtypes'].most_common(10):
            f.write(f"  {k}: {v:,}\n")
            
        f.write("\n--- WEIRD EVENTS (Top 10) ---\n")
        for k, v in global_stats['weird_names'].most_common(10):
            f.write(f"  {k}: {v:,}\n")

if __name__ == '__main__':
    main()
