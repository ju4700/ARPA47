#!/bin/bash
cat << 'EOF' > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = gLcl6pgL1E9JyTeZenqt261/mQzVpU9XddOl5R1raUU=
Address = 10.255.255.2/30
ListenPort = 51820

[Peer]
PublicKey = IS3KyE5TZ28HvKgnMMRXK1ldkwuXY8ekUbDncGYhmXA=
AllowedIPs = 10.255.255.1/32
Endpoint = 103.148.177.2:51820
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl restart wg-quick@wg0
wg show
