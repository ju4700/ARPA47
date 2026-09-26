import pandas as pd
import os

STATS_DIR = r"F:\ARPA47-Dataset\statistics"

def verify():
    # 1. Connection Stats
    conn_df = pd.read_csv(os.path.join(STATS_DIR, "conn_daily_summary.csv"))
    total_conns = conn_df['Total_Connections'].sum()
    tcp_conns = conn_df['TCP_Conns'].sum()
    udp_conns = conn_df['UDP_Conns'].sum()
    
    # 2. SSL Stats
    ssl_df = pd.read_csv(os.path.join(STATS_DIR, "ssl_daily_summary.csv"))
    total_tls = ssl_df['Total_TLS_Connections'].sum()
    tls_12 = ssl_df['TLS_1_2'].sum()
    tls_13_ecdhe = ssl_df['TLS_1_3_no_PQC'].sum()
    pqc = ssl_df['PQC_Connections'].sum()
    hidden_sni = ssl_df['Hidden_SNI'].sum()
    ech = ssl_df['Genuine_ECH'].sum()
    
    # 3. QUIC Stats
    quic_df = pd.read_csv(os.path.join(STATS_DIR, "quic_daily_summary.csv"))
    total_quic = quic_df['Total_QUIC_Connections'].sum()
    quic_hidden_sni = quic_df['Hidden_SNI'].sum()
    
    # 4. DNS Stats
    dns_df = pd.read_csv(os.path.join(STATS_DIR, "dns_daily_summary.csv"))
    total_dns = dns_df['Total_Queries'].sum()
    dns_a = dns_df['Type_A'].sum()
    dns_aaaa = dns_df['Type_AAAA'].sum()
    dns_https = dns_df['Type_HTTPS'].sum()
    
    # Print the verification checks
    print("--- DATA INTEGRITY VERIFICATION ---")
    print(f"Total Connections: {total_conns} (Expected: 31338265) -> {'PASS' if total_conns == 31338265 else 'FAIL'}")
    print(f"Total TLS: {total_tls} (Expected: 2712288) -> {'PASS' if total_tls == 2712288 else 'FAIL'}")
    print(f"Total QUIC: {total_quic} (Expected: 4236252) -> {'PASS' if total_quic == 4236252 else 'FAIL'}")
    
    quic_percent = round((total_quic / (total_tls + total_quic)) * 100, 1)
    print(f"QUIC % of Port 443: {quic_percent}% (Expected: 61.0%) -> {'PASS' if quic_percent == 61.0 else 'FAIL'}")
    
    pqc_percent = round((pqc / total_tls) * 100, 2)
    print(f"PQC adoption: {pqc} / {pqc_percent}% (Expected: 626107 / 23.08%) -> {'PASS' if pqc == 626107 and pqc_percent == 23.08 else 'FAIL'}")
    
    tls_hidden_sni_pct = round((hidden_sni / total_tls) * 100, 2)
    print(f"TLS Hidden SNI: {hidden_sni} / {tls_hidden_sni_pct}% (Expected: 384139 / 14.16%) -> {'PASS' if hidden_sni == 384139 and tls_hidden_sni_pct == 14.16 else 'FAIL'}")
    
    ech_percent = round((ech / total_tls) * 100, 2)
    print(f"Genuine ECH: {ech} / {ech_percent}% (Expected: 2822 / 0.10%) -> {'PASS' if ech == 2822 and ech_percent == 0.10 else 'FAIL'}")
    
    quic_hidden_pct = round((quic_hidden_sni / total_quic) * 100, 1)
    print(f"QUIC Hidden SNI %: {quic_hidden_pct}% (Expected: 77.4%) -> {'PASS' if quic_hidden_pct == 77.4 else 'FAIL'}")
    
    print(f"Total DNS Queries: {total_dns} (Expected: 7637226) -> {'PASS' if total_dns == 7637226 else 'FAIL'}")
    
    dns_https_pct = round((dns_https / total_dns) * 100, 2)
    print(f"DNS HTTPS RR %: {dns_https_pct}% (Expected: 3.39%) -> {'PASS' if dns_https_pct == 3.39 else 'FAIL'}")
    
if __name__ == "__main__":
    verify()
