# ARPA47: Passive Measurement of QUIC and ECH at the ISP Edge

This repository contains the measurement infrastructure, analytical scripts, and paper drafts for a study on TLS 1.3, Encrypted Client Hello (ECH), and QUIC protocol adoption. The research relies on passive telemetry gathered directly from a South Asian residential Internet Service Provider (ISP).

The project studies the "Going Dark" phenomenon in network traffic engineering. Widespread encryption limits the visibility ISPs historically relied on for quality of service management and traffic classification. This infrastructure addresses these limitations by running deep packet inspection (DPI) at the provider edge.

## Repository Structure

* `Mikrotik Scripts/`: RouterOS and Node.js scripts used to control the ISP core routers. This includes logic to bypass hardware FastTrack processing and force full bidirectional mirroring of encrypted traffic via TZSP.
* `Info/`: Documentation detailing the engineering challenges of conducting passive network telemetry in an emerging market. Topics include handling ungraceful power failures, stateful firewall (SPI) resets, and dynamic IP routing.
* `Paper 1/` & `Paper 2/`: Drafts of the academic research papers derived from the collected dataset.
* `sample_data/`: Anonymized samples of Zeek TLS logs alongside the Python scripts used to calculate adoption metrics and parse cipher suites.

## Collection Architecture

The data pipeline operates on two distinct layers:

1. **Macroscopic (NetFlow):** Baseline traffic volume and routing metrics are exported via IPFIX and collected using `nfcapd`.
2. **Microscopic (TZSP/Zeek):** A subset of traffic is mirrored from the ISP router via TZSP to a local Linux collection server. A custom Python decapper unwraps the Ethernet frames and passes them to Zeek via a virtual TAP interface (`arpa-tap0`) to extract Server Name Indications (SNI), TLS versions, and Post-Quantum cryptography parameters.

## Setup Requirements

Deploying this infrastructure requires:
- Administrative access to a MikroTik core router capable of traffic flow exports and mangle rules.
- A dedicated Linux server configured with `firewalld` to accept incoming UDP streams on specific ports.
- Proper network configuration to ensure consumer NAT routers do not block fragmented TZSP packets via aggressive SPI firewalls.
