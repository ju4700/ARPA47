# APEX-IDS2026 Honeyport Deployment Script
# Run this on your Mikrotik Terminal to vastly expand the honeypot surface area.
# This script creates low-interaction traps on highly scanned ports (23, 445, 1433, 3389)
# across your entire 103.146.76.0/24 and 103.148.176.0/24 public blocks.

/ip firewall nat

# ----------------------------------------------------
# 1. Honeyports for Block: 103.146.76.0/24
# ----------------------------------------------------
# Telnet (Mirai/IoT Botnets)
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=23 protocol=tcp dst-address=103.146.76.0/24 dst-port=23 comment="HONEYPORT-TELNET-BLK1"
# SMB (WannaCry/Ransomware)
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=445 protocol=tcp dst-address=103.146.76.0/24 dst-port=445 comment="HONEYPORT-SMB-BLK1"
# MSSQL (Database Bruteforcers)
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=1433 protocol=tcp dst-address=103.146.76.0/24 dst-port=1433 comment="HONEYPORT-MSSQL-BLK1"
# RDP (Ransomware Access Brokers)
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=3389 protocol=tcp dst-address=103.146.76.0/24 dst-port=3389 comment="HONEYPORT-RDP-BLK1"

# ----------------------------------------------------
# 2. Honeyports for Block: 103.148.176.0/24
# (Excluding the Honeypot itself: !103.148.176.62)
# ----------------------------------------------------
# Telnet
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=23 protocol=tcp dst-address=103.148.176.0/24 dst-address=!103.148.176.62 dst-port=23 comment="HONEYPORT-TELNET-BLK2"
# SMB
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=445 protocol=tcp dst-address=103.148.176.0/24 dst-address=!103.148.176.62 dst-port=445 comment="HONEYPORT-SMB-BLK2"
# MSSQL
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=1433 protocol=tcp dst-address=103.148.176.0/24 dst-address=!103.148.176.62 dst-port=1433 comment="HONEYPORT-MSSQL-BLK2"
# RDP
add chain=dstnat action=dst-nat to-addresses=103.148.176.62 to-ports=3389 protocol=tcp dst-address=103.148.176.0/24 dst-address=!103.148.176.62 dst-port=3389 comment="HONEYPORT-RDP-BLK2"

# ----------------------------------------------------
# Ensure Honeypot Logging captures these NAT'd packets
# AND enforce Zero Egress Policy (prevent pivot attacks)
# ----------------------------------------------------
/ip firewall filter
add chain=forward action=log dst-address=103.148.176.62 connection-nat-state=dstnat log-prefix="HONEYPORT-HIT" comment="HONEYPOT-LOG-NAT-TRAPS"
add chain=forward action=drop src-address=103.148.176.62 connection-state=new comment="ZERO-EGRESS: Prevent Honeypot Pivot"
