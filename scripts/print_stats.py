import pandas as pd

print("=== SSL DAILY SUMMARY ===")
ssl = pd.read_csv(r"F:\ARPA47-Dataset\statistics\ssl_daily_summary.csv")
print(ssl.to_string(index=False))

total_tls = ssl["Total_TLS_Connections"].sum()
total_tls13 = ssl["TLS1.3_Connections"].sum()
total_pqc = ssl["PQC_Connections"].sum()
print(f"\nTOTALS:")
print(f"  Total TLS connections : {total_tls:,}")
print(f"  Total TLS 1.3         : {total_tls13:,}  ({total_tls13/total_tls*100:.1f}%)")
print(f"  Total PQC connections : {total_pqc:,}  ({total_pqc/total_tls*100:.2f}%)")

print("\n=== QUIC DAILY SUMMARY ===")
quic = pd.read_csv(r"F:\ARPA47-Dataset\statistics\quic_daily_summary.csv")
print(quic.to_string(index=False))
print(f"\n  Total QUIC connections: {quic['Total_QUIC_Connections'].sum():,}")

print("\n=== CONN DAILY SUMMARY ===")
conn = pd.read_csv(r"F:\ARPA47-Dataset\statistics\conn_daily_summary.csv")
print(conn.to_string(index=False))
print(f"\n  Total connections     : {conn['Total_Connections'].sum():,}")
print(f"  Total traffic         : {conn['Total_Traffic_GB'].sum():.1f} GB")
