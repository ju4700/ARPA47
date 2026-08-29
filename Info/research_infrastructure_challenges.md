# The Impact of Power Grid Fluctuations on Passive Network Measurement

When conducting passive network telemetry studies in emerging markets (e.g., South Asia), power grid instability introduces severe engineering challenges that are rarely documented in Western-centric academic literature. 

A power outage does not just create a gap in the data; it triggers a cascade of state-resets across the collection infrastructure that can silently corrupt or block subsequent data collection even after power is restored.

Below are the primary failure domains we observed during our 7-day collection period when the measurement site experienced an ungraceful power loss.

## 1. Consumer Router SPI Firewall & UDP Fragmentation Drops
**The Phenomenon:** Our dual-layered collection pipeline relies on two UDP streams passing through a consumer-grade NAT router (Netis):
*   **NetFlow (Port 2055):** Small packets (< 1000 bytes)
*   **TZSP Mirroring (Port 37008):** Massive, fragmented packets (> 1500 bytes)

**The Failure:** Before the power outage, both streams successfully traversed the router's port forwarding rules. Following an ungraceful reboot, the Netis router's internal Stateful Packet Inspection (SPI) firewall reset its active connection tracking states. Because TZSP packets encapsulate full Ethernet frames, they exceed standard MTU and are heavily fragmented. Upon reboot, the router's SPI firewall interpreted the sudden influx of massive, fragmented UDP packets as a UDP Flood/DoS attack and silently dropped them.

**The Result:** The Linux server continued receiving NetFlow data perfectly, creating the illusion of a healthy network, while the Zeek analyzer was completely starved of TLS/QUIC metadata. 

**The Mitigation:** Traditional port-forwarding is insufficient for fragmented UDP under ungraceful reboots. The collection server had to be placed in the router's Demilitarized Zone (DMZ), bypassing the consumer SPI firewall entirely and shifting the firewalling responsibility exclusively to the Linux server's internal `firewalld`.

## 2. Volatile Firewall State on Linux Collection Servers
**The Phenomenon:** When establishing the collection pipeline, network engineers frequently use temporary `iptables` or `firewalld` commands to open listening ports (e.g., `firewall-cmd --add-port=37008/udp`) during the testing phase.

**The Failure:** When the server loses power, any firewall rule not explicitly committed to disk via a `--permanent` flag is wiped. 
**The Result:** The server boots back up, the systemd services (Zeek, decapper) start successfully, but the kernel drops all incoming traffic. This requires rigorous configuration management to ensure all required ports survive cold reboots.

## 3. Dynamic IP Churn and Sniff Target Misalignment
**The Phenomenon:** ISP core routers (like the MikroTik) use explicit firewall mangle rules to duplicate and route TZSP packets to a specific destination IP address. 
**The Failure:** In environments where the collection server sits behind a dynamic PPPoE/DHCP connection, a power outage forces a modem reconnection. If the collection site receives a new public IP address, the MikroTik core router will continue blindly firing gigabytes of mirrored traffic at the old, dead IP address until the mangle rules are manually updated.

## Conclusion for Research Methodology
Studies conducted in these environments must account for "silent failures" where services appear active (`systemctl status active`) but network-layer state resets (SPI blocks, MTU fragmentation drops) prevent data ingestion. Researchers must build robust out-of-band alerting (e.g., triggering alerts if Zeek's `conn.log` grows by 0 bytes over a 15-minute window) to detect these infrastructure anomalies before they ruin the longitudinal integrity of the dataset.
