#!/bin/bash
# ==============================================================================
# APEX-IDS2026: Application-Layer Deception Setup (Phase 3)
# Run this script on your HONEYPOT SERVER (103.148.176.62)
# ==============================================================================

echo "=== APEX-IDS2026 Application-Layer Deception Setup ==="

# 1. Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    rm get-docker.sh
fi

# 2. Setup Honeytokens (Fake Post-Exploitation Files)
echo "[*] Generating Honeytokens..."
mkdir -p /root/.aws
mkdir -p /etc/mysql/
mkdir -p /var/www/html/config

# Dummy AWS Keys (If attacker tries to use these, AWS CloudTrail logs the failure)
cat << 'EOF' > /root/.aws/credentials
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
chmod 600 /root/.aws/credentials

# Dummy Database Config (If attacker steals this, we know they are looking for DBs)
cat << 'EOF' > /var/www/html/config/database.env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASS=Sup3rS3cr3tM4st3rP4ssw0rd!
DB_NAME=production_customers
EOF

echo "[*] Honeytokens Injected!"

# 3. Setup IoT & ICS Emulators (Docker)
echo "[*] Deploying IoT (MQTT/CoAP) and ICS (Modbus/S7) Honeypots..."

mkdir -p /opt/iot-honeypot
cd /opt/iot-honeypot

cat << 'EOF' > docker-compose.yml
version: '3.3'
services:
  # Conpot - Industrial Control Systems (ICS/SCADA) Emulator
  conpot:
    image: honeyproject/conpot:latest
    restart: always
    ports:
      - "502:502"      # Modbus
      - "102:102"      # Siemens S7
      - "161:161/udp"  # SNMP
      - "47808:47808/udp" # BACnet
    command: --template default

  # Eclipse Mosquitto (Acting as a fake vulnerable IoT MQTT Broker)
  mqtt-honeypot:
    image: eclipse-mosquitto:1.6
    restart: always
    ports:
      - "1883:1883"
    command: mosquitto -c /mosquitto-no-auth.conf
EOF

cat << 'EOF' > mosquitto-no-auth.conf
listener 1883
allow_anonymous true
EOF

docker compose up -d

echo "=== SETUP COMPLETE ==="
echo "Your honeypot is now fully weaponized with AWS Honeytokens and IoT/ICS Protocols!"
