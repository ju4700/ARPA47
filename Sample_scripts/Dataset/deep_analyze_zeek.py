import os
import gzip
import csv
from collections import Counter
from multiprocessing import Pool
from tqdm import tqdm

ARCHIVE_DIR = r"F:\ARPA47\zeek_archive"
OUTPUT_FILE = r"d:\Development\ARPA47\Paper 1\DIB2\Comprehensive_Zeek_Analysis.md"

def analyze_hour(folder_path):
    stats = {
        'total_conn': 0,
        'conn_protos': Counter(),
        'conn_services': Counter(),
        'conn_states': Counter(),
        'conn_orig_bytes': 0,
        'conn_resp_bytes': 0,

        'total_ssl': 0,
        'tls_versions': Counter(),
        'tls_ciphers': Counter(),
        'tls_curves': Counter(),
        'tls_alpns': Counter(),
        'tls_ech_outer_snis': Counter(),
        
        'total_quic': 0,
        'quic_versions': Counter(),
        'quic_missing_sni': 0,
        'quic_alpns': Counter(),
        
        'total_dns': 0,
        'dns_qtypes': Counter(),
        'dns_rcodes': Counter(),
        
        'total_http': 0,
        'http_methods': Counter(),
        'http_versions': Counter(),

        'total_weird': 0,
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
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) >= 12:
                            stats['total_conn'] += 1
                            stats['conn_protos'][row[6]] += 1
                            service = row[7]
                            if service != '-': stats['conn_services'][service] += 1
                            stats['conn_states'][row[11]] += 1
                            
                            orig_b = row[9]
                            resp_b = row[10]
                            if orig_b != '-': stats['conn_orig_bytes'] += int(orig_b)
                            if resp_b != '-': stats['conn_resp_bytes'] += int(resp_b)
            except Exception: pass

        # 2. ssl.log
        elif file.startswith("ssl"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 12:
                            stats['total_ssl'] += 1
                            version = row[6]
                            cipher = row[7]
                            curve = row[8]
                            server_name = row[9]
                            alpn = row[12]
                            
                            if version != '-': stats['tls_versions'][version] += 1
                            if cipher != '-': stats['tls_ciphers'][cipher] += 1
                            if curve != '-': stats['tls_curves'][curve] += 1
                            if alpn != '-': stats['tls_alpns'][alpn] += 1
                            if 'ech' in server_name.lower(): 
                                stats['tls_ech_outer_snis'][server_name] += 1
            except Exception: pass

        # 3. quic.log
        elif file.startswith("quic"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 11:
                            stats['total_quic'] += 1
                            version = row[6]
                            server_name = row[10]
                            alpn = row[11]
                            
                            if version != '-': stats['quic_versions'][version] += 1
                            if alpn != '-': stats['quic_alpns'][alpn] += 1
                            if server_name == '-': stats['quic_missing_sni'] += 1
            except Exception: pass
            
        # 4. dns.log
        elif file.startswith("dns"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 15:
                            stats['total_dns'] += 1
                            qtype = row[13]
                            rcode = row[15]
                            if qtype != '-': stats['dns_qtypes'][qtype] += 1
                            if rcode != '-': stats['dns_rcodes'][rcode] += 1
            except Exception: pass

        # 5. http.log
        elif file.startswith("http"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 7:
                            stats['total_http'] += 1
                            method = row[7]
                            version = row[11] if len(row) > 11 else '-'
                            if method != '-': stats['http_methods'][method] += 1
                            if version != '-': stats['http_versions'][version] += 1
            except Exception: pass

        # 6. weird.log
        elif file.startswith("weird"):
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader((line for line in f if not line.startswith('#')), delimiter='\t')
                    for row in reader:
                        if len(row) > 6:
                            stats['total_weird'] += 1
                            name = row[6]
                            stats['weird_names'][name] += 1
            except Exception: pass

    return stats

def main():
    folders = [os.path.join(ARCHIVE_DIR, d) for d in os.listdir(ARCHIVE_DIR) if os.path.isdir(os.path.join(ARCHIVE_DIR, d))]
    
    gs = {
        'total_conn': 0, 'conn_protos': Counter(), 'conn_services': Counter(), 'conn_states': Counter(), 
        'conn_orig_bytes': 0, 'conn_resp_bytes': 0,
        
        'total_ssl': 0, 'tls_versions': Counter(), 'tls_ciphers': Counter(), 'tls_curves': Counter(), 
        'tls_alpns': Counter(), 'tls_ech_outer_snis': Counter(),
        
        'total_quic': 0, 'quic_versions': Counter(), 'quic_missing_sni': 0, 'quic_alpns': Counter(),
        
        'total_dns': 0, 'dns_qtypes': Counter(), 'dns_rcodes': Counter(),
        
        'total_http': 0, 'http_methods': Counter(), 'http_versions': Counter(),
        
        'total_weird': 0, 'weird_names': Counter(),
    }
    
    with Pool(os.cpu_count()) as pool:
        results = list(tqdm(pool.imap_unordered(analyze_hour, folders), total=len(folders)))
        
    for r in results:
        gs['total_conn'] += r['total_conn']
        gs['conn_orig_bytes'] += r['conn_orig_bytes']
        gs['conn_resp_bytes'] += r['conn_resp_bytes']
        gs['total_ssl'] += r['total_ssl']
        gs['total_quic'] += r['total_quic']
        gs['quic_missing_sni'] += r['quic_missing_sni']
        gs['total_dns'] += r['total_dns']
        gs['total_http'] += r['total_http']
        gs['total_weird'] += r['total_weird']
        
        gs['conn_protos'].update(r['conn_protos'])
        gs['conn_services'].update(r['conn_services'])
        gs['conn_states'].update(r['conn_states'])
        gs['tls_versions'].update(r['tls_versions'])
        gs['tls_ciphers'].update(r['tls_ciphers'])
        gs['tls_curves'].update(r['tls_curves'])
        gs['tls_alpns'].update(r['tls_alpns'])
        gs['tls_ech_outer_snis'].update(r['tls_ech_outer_snis'])
        gs['quic_versions'].update(r['quic_versions'])
        gs['quic_alpns'].update(r['quic_alpns'])
        gs['dns_qtypes'].update(r['dns_qtypes'])
        gs['dns_rcodes'].update(r['dns_rcodes'])
        gs['http_methods'].update(r['http_methods'])
        gs['http_versions'].update(r['http_versions'])
        gs['weird_names'].update(r['weird_names'])

    def top(counter, n=15):
        s = ""
        for k, v in counter.most_common(n):
            s += f"| `{k}` | {v:,} |\n"
        return s

    md = f"""# Comprehensive Raw Zeek Data Analysis
**Source:** `F:\\ARPA47\\zeek_archive`
**Folders Scanned:** {len(folders)} (32 days of hourly logs)

## 1. Global Volume Overview
| Log File | Total Records |
|---|---|
| **conn.log** | {gs['total_conn']:,} |
| **ssl.log** | {gs['total_ssl']:,} |
| **quic.log** | {gs['total_quic']:,} |
| **dns.log** | {gs['total_dns']:,} |
| **http.log** | {gs['total_http']:,} |
| **weird.log** | {gs['total_weird']:,} |

**Total IP Payload Recorded:** 
- Originator (Upload): {gs['conn_orig_bytes'] / (1024**4):.2f} TB
- Responder (Download): {gs['conn_resp_bytes'] / (1024**4):.2f} TB
*(Note: These byte counts are susceptible to inflation due to Zeek sequence estimation on dropped packets)*

---

## 2. Connection Analytics (`conn.log`)
### Protocols
| Protocol | Count |
|---|---|
{top(gs['conn_protos'], 5)}

### Top Services
| Service | Count |
|---|---|
{top(gs['conn_services'], 10)}

### Connection States
| State | Count |
|---|---|
{top(gs['conn_states'], 15)}

---

## 3. TLS Cryptographic Profile (`ssl.log`)
### TLS Versions
| Version | Count |
|---|---|
{top(gs['tls_versions'], 10)}

### Key Exchange Curves (PQC Tracking)
| Curve | Count |
|---|---|
{top(gs['tls_curves'], 10)}

### ECH Outer SNIs Found
| Outer SNI | Count |
|---|---|
{top(gs['tls_ech_outer_snis'], 10)}

### ALPN Extensions (Next Protocol)
| ALPN | Count |
|---|---|
{top(gs['tls_alpns'], 10)}

---

## 4. HTTP/3 QUIC Traffic (`quic.log`)
- **Total QUIC Sessions:** {gs['total_quic']:,}
- **Sessions Missing SNI:** {gs['quic_missing_sni']:,} ({(gs['quic_missing_sni']/gs['total_quic'])*100 if gs['total_quic'] else 0:.2f}% Blindness Rate)

### QUIC Versions
| Version | Count |
|---|---|
{top(gs['quic_versions'], 10)}

### QUIC ALPNs
| ALPN | Count |
|---|---|
{top(gs['quic_alpns'], 10)}

---

## 5. DNS Analytics (`dns.log`)
### Query Types
| QType Name | Count |
|---|---|
{top(gs['dns_qtypes'], 15)}

### Response Codes
| RCode Name | Count |
|---|---|
{top(gs['dns_rcodes'], 10)}

---

## 6. Legacy HTTP (`http.log`)
### Top Methods
| Method | Count |
|---|---|
{top(gs['http_methods'], 10)}

### Versions
| Version | Count |
|---|---|
{top(gs['http_versions'], 10)}

---

## 7. Sensor Integrity & Anomalies (`weird.log`)
### Top Weird Events
| Event Name | Count |
|---|---|
{top(gs['weird_names'], 15)}
"""
    with open(OUTPUT_FILE, "w", encoding='utf-8') as f:
        f.write(md)
    print(f"Analysis saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
