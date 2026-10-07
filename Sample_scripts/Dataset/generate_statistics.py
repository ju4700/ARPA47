import zipfile
import pandas as pd
import io
import os
import duckdb

OUTPUT_DIR = r"F:\ARPA47-Dataset\ARPA47_Release"

def analyze_zip(zip_path, log_type):
    print(f"Analyzing {zip_path}...")
    daily_stats = []
    
    with zipfile.ZipFile(zip_path, 'r') as z:
        for fname in z.namelist():
            if not fname.endswith('.parquet'): continue
            
            day = fname.split('_')[1].split('.parquet')[0]
            with z.open(fname) as f:
                df = pd.read_parquet(io.BytesIO(f.read()))
                
                if log_type == 'conn':
                    daily_stats.append({
                        'date': day,
                        'total_connections': len(df),
                        'tcp_count': len(df[df['proto'] == 'tcp']),
                        'udp_count': len(df[df['proto'] == 'udp']),
                        'icmp_count': len(df[df['proto'] == 'icmp'])
                    })
                elif log_type == 'ssl':
                    daily_stats.append({
                        'date': day,
                        'total_tls': len(df),
                        'tls_1_2': len(df[df['version'] == 'TLSv12']),
                        'tls_1_3': len(df[df['version'] == 'TLSv13']),
                        'pqc_x25519mlkem768': len(df[df['curve'] == 'X25519MLKEM768']),
                        'ech_sessions': len(df[df['server_name'].str.contains('cloudflare-ech', na=False)])
                    })
                elif log_type == 'quic':
                    daily_stats.append({
                        'date': day,
                        'total_quic': len(df),
                        'hidden_sni': len(df[df['server_name'].isna() | (df['server_name'] == '') | (df['server_name'] == '-')])
                    })
                elif log_type == 'dns':
                    daily_stats.append({
                        'date': day,
                        'total_queries': len(df),
                        'https_rr_queries': len(df[df['qtype_name'] == 'HTTPS'])
                    })
                    
    return pd.DataFrame(daily_stats).sort_values('date')

if __name__ == '__main__':
    conn_df = analyze_zip(os.path.join(OUTPUT_DIR, 'arpa47_conn.zip'), 'conn')
    conn_df.to_csv(os.path.join(OUTPUT_DIR, 'conn_daily_summary.csv'), index=False)
    
    ssl_df = analyze_zip(os.path.join(OUTPUT_DIR, 'arpa47_ssl.zip'), 'ssl')
    ssl_df.to_csv(os.path.join(OUTPUT_DIR, 'ssl_daily_summary.csv'), index=False)
    
    quic_df = analyze_zip(os.path.join(OUTPUT_DIR, 'arpa47_quic.zip'), 'quic')
    quic_df.to_csv(os.path.join(OUTPUT_DIR, 'quic_daily_summary.csv'), index=False)
    
    dns_df = analyze_zip(os.path.join(OUTPUT_DIR, 'arpa47_dns.zip'), 'dns')
    dns_df.to_csv(os.path.join(OUTPUT_DIR, 'dns_daily_summary.csv'), index=False)
    
    with zipfile.ZipFile(os.path.join(OUTPUT_DIR, 'statistics.zip'), 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(os.path.join(OUTPUT_DIR, 'conn_daily_summary.csv'), 'conn_daily_summary.csv')
        zf.write(os.path.join(OUTPUT_DIR, 'ssl_daily_summary.csv'), 'ssl_daily_summary.csv')
        zf.write(os.path.join(OUTPUT_DIR, 'quic_daily_summary.csv'), 'quic_daily_summary.csv')
        zf.write(os.path.join(OUTPUT_DIR, 'dns_daily_summary.csv'), 'dns_daily_summary.csv')
        
    os.remove(os.path.join(OUTPUT_DIR, 'conn_daily_summary.csv'))
    os.remove(os.path.join(OUTPUT_DIR, 'ssl_daily_summary.csv'))
    os.remove(os.path.join(OUTPUT_DIR, 'quic_daily_summary.csv'))
    os.remove(os.path.join(OUTPUT_DIR, 'dns_daily_summary.csv'))
    print("statistics.zip successfully created!")
