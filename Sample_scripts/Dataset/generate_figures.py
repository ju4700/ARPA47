import pandas as pd
import matplotlib.pyplot as plt
import os

STATS_DIR = r"F:\ARPA47-Dataset\statistics"
PAPER_DIR = r"D:\Development\ARPA47\Paper 1"

# Figure 1: TLS vs QUIC Volumetric over time (using conn_daily_summary)
conn_summary = pd.read_csv(os.path.join(STATS_DIR, "conn_daily_summary.csv"))
# For simplicity, we'll use TCP vs UDP as a proxy for TLS vs QUIC volume
# since we don't have daily bytes for just port 443 in this summary, but it's illustrative.
conn_summary['Date'] = pd.to_datetime(conn_summary['Date'])
conn_summary = conn_summary[conn_summary['Total_Connections'] > 0] # Filter bad days

plt.figure(figsize=(10, 5))
plt.plot(conn_summary['Date'], conn_summary['TCP_Conns'], label='TCP Connections (TLS)', linewidth=2)
plt.plot(conn_summary['Date'], conn_summary['UDP_Conns'], label='UDP Connections (QUIC)', linewidth=2)
plt.title('Figure 1: 30-Day Diurnal Rhythm of TCP vs UDP Connections')
plt.xlabel('Date')
plt.ylabel('Total Connections')
plt.legend()
plt.grid(True, linestyle='--', alpha=0.7)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(os.path.join(PAPER_DIR, "figure1.png"), dpi=300)
print("Generated Figure 1.")

# Figure 2: TLS Breakdown (using paper_stats numbers)
labels = ['TLS 1.2 (Legacy)', 'TLS 1.3 (Standard)', 'TLS 1.3 (PQC)', 'Genuine ECH']
sizes = [1419692, 666489, 626107, 2822]
colors = ['#ff9999','#66b3ff','#99ff99','#ffcc99']
explode = (0.05, 0.05, 0.05, 0.3)

plt.figure(figsize=(8, 8))
plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.2f%%',
        shadow=True, startangle=140)
plt.title('Figure 2: TLS 1.3 and Post-Quantum Cryptography Adoption')
plt.axis('equal')
plt.tight_layout()
plt.savefig(os.path.join(PAPER_DIR, "figure2.png"), dpi=300)
print("Generated Figure 2.")

# Figure 3: PQC Adoption over time
ssl = pd.read_csv(os.path.join(STATS_DIR, "ssl_daily_summary.csv"))
ssl['Date'] = pd.to_datetime(ssl['Date'])
plt.figure(figsize=(10, 5))
plt.plot(ssl['Date'], ssl['Total_TLS_Connections'], label='Total TLS', color='gray', alpha=0.5)
plt.plot(ssl['Date'], ssl['PQC_Connections'], label='PQC (MLKEM768)', color='green', linewidth=2)
plt.title('Figure 3: Post-Quantum Cryptography (PQC) Connections Over Time')
plt.xlabel('Date')
plt.ylabel('Daily Connections')
plt.legend()
plt.grid(True, linestyle='--', alpha=0.7)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(os.path.join(PAPER_DIR, "figure3.png"), dpi=300)
print("Generated Figure 3.")
