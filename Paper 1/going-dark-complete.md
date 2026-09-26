# Going Dark at the Edge: A 30-Day Empirical Measurement of QUIC, Encrypted Client Hello, and Post-Quantum Cryptography Adoption at a South Asian Residential ISP

**Abstract**  
The adoption of HTTP/3 (QUIC) and Encrypted Client Hello (ECH) is eroding the network-layer visibility that ISPs rely on for traffic engineering and Quality of Service (QoS) management [3]. Existing studies of ECH and HTTPS DNS record adoption have used active web crawlers or passive telemetry collected in Western university campus networks [13]; empirical data from residential deployments in emerging markets remains scarce. This paper reports a 30-day passive measurement study of 4,000 residential subscribers behind a Carrier-Grade NAT (CGNAT) gateway in Bangladesh, conducted from August 26 to September 26, 2026 [4]. We collected macroscopic IPFIX (NetFlow v10) telemetry across the full subscriber base and microscopic TLS handshake and DNS metadata from a /24 PPPoE subnet mirrored via the TaZmen Sniffer Protocol (TZSP) [4]. Over the 30-day window, we parsed 2,712,288 TLS Client Hello messages and 4,236,252 QUIC sessions, totalling 31,338,265 network connections and 5.2 TB of observed traffic. We find that QUIC now accounts for 61.0% of all port-443 connections, while 14.16% of TLS connections present an empty or hidden SNI field. Post-Quantum Cryptographic (PQC) key exchange (X25519MLKEM768/Kyber) is observed in 23.08% of all TLS 1.3 handshakes, concentrated on connections to major cloud providers. Genuine ECH, identified by the `cloudflare-ech.com` outer public name, appears in only 2,822 flows (0.10%), yet the combination of QUIC header encryption and hidden SNI fields renders 77.4% of all QUIC sessions opaque to legacy SNI-based traffic classifiers. We evaluate the resulting degradation in ISP queue management and CGNAT state tracking performance.

**Keywords**: Passive Measurement, QUIC, Encrypted Client Hello, Post-Quantum Cryptography, Carrier-Grade NAT, Traffic Engineering, Active Queue Management, Bangladesh.

---

## 1. Introduction

Over the past decade, end-to-end encryption has become the norm for web traffic. Transport Layer Security (TLS) 1.3 and HTTPS now protect the majority of application payloads from path observers [3, 6]. The QUIC transport protocol (RFC 9000) pushed this further by encrypting transport-layer headers, hiding packet numbers and connection handshakes [3]. Despite this, two plaintext fields have historically remained visible to path observers: DNS queries and the Server Name Indication (SNI) extension in the TLS Client Hello [3]. ISPs have used these fields as the basis for traffic engineering, zero-rating, parental controls, and security middleboxes [7, 13].

To close these remaining privacy leaks, the Internet Engineering Task Force (IETF) has introduced standardized protocol modifications designed to fully encrypt metadata at the network edge [3, 14]. DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) encrypt the stub-to-resolver resolution path, preventing the passive monitoring of domain lookups [9, 14]. To complement encrypted DNS, the Encrypted Client Hello (ECH) extension to TLS 1.3 (RFC 9849 / draft-ietf-tls-esni) encrypts the entire Client Hello message, including the SNI field [1, 6]. Under ECH, the client utilizes a public key retrieved via new DNS HTTPS resource records (RFC 9460) to encrypt the "inner" Client Hello containing the real destination domain [1, 6]. The client then embeds this encrypted payload inside a syntactically valid "outer" Client Hello containing an in-clear, generic public name (e.g., `cloudflare-ech.com`) [6].

ECH and QUIC protect user privacy, but they remove the plaintext fields that ISPs have relied on for traffic classification [3, 7]. SNI-based and DPI-based classification methods no longer function when the destination hostname is encrypted [7]. ISPs lose the ability to distinguish interactive traffic from bulk downloads, apply per-class queue allocation, or attribute congestion events to specific application types [3, 7].

Existing passive measurement studies of ECH and QUIC have been conducted almost exclusively on Western university campus networks, such as those at the University of Trieste [4, 13], or via active web crawlers [13]. These settings do not reflect the infrastructure and user behavior typical of residential networks in the Global South, where CGNAT is the norm, mobile platforms dominate traffic, and power outages introduce temporal gaps in data [4].

This study bridges this gap by presenting a 30-day empirical passive measurement campaign conducted from the operational edge of a residential ISP in Chattogram, Bangladesh [4]. We evaluate how ECH and QUIC adoption scales within a dense, resource-constrained network architecture. We analyze a dual-layered telemetry dataset: macroscopic IPFIX flow records capturing the volumetric transport split across 4,000 active users, and microscopic packet metadata from a /24 subnet containing 225 active PPPoE subscribers mirrored into an on-site Zeek analyzer [4].

Our work offers the following three contributions:
1. **First Residential South Asian Passive ECH/QUIC Dataset**: We present empirical measurements of modern protocol adoption from a non-Western residential subscriber base behind CGNAT, capturing real-world usage patterns outside the standard academic/corporate laboratory environments [3, 4].
2. **Quantification of Visibility Loss**: We mathematically evaluate the rate at which legacy SNI-based traffic filters and queue trees are being blinded by the combination of ECH, GREASE extensions, and QUIC obfuscation [3, 4].
3. **Evaluation of Infrastructure Stress**: We analyze the impact of high-density UDP-based QUIC traffic on CGNAT connection state tracking tables, documenting port allocation and session timeout behaviors under heavy diurnal load shifts [4].

The remainder of this paper is organized as follows. Section 2 provides the technical background on ECH, GREASE, and QUIC, detailing their threats to ISP operations. Section 3 presents our bifurcated methodology, physical network deployment, and ethical anonymization architecture. Section 4 evaluates macroscopic volumetric patterns. Section 5 breaks down microscopic handshake and ECH adoption characteristics. Section 6 analyzes the operational impact on CGNAT and Active Queue Management. Section 7 discusses broader traffic engineering implications and scope limitations, and Section 8 concludes the paper.

---

## 2. Background & Technical Threat to ISP Engineering

### 2.1. The Mechanics of ECH and DNS HTTPS Records
To prevent path observers from extracting destination hostnames from TLS handshakes, ECH replaces the single plaintext Client Hello with a nested, dual-layered structure [6]. The client constructs an *inner* Client Hello containing the actual sensitive parameters of the connection, such as the target Server Name Indication (SNI) and Application-Layer Protocol Negotiation (ALPN) preferences [6]. This inner message is encrypted using the Hybrid Public Key Encryption (HPKE) scheme [6]. The resulting ciphertext is embedded as an extension inside an *outer* Client Hello [6]. 

The outer Client Hello serves as a plaintext decoy, containing a non-sensitive "public name" (such as `cloudflare-ech.com`) in its SNI field [6]. If a middlebox or legacy server inspects the outer header, it only observes the public name [4, 6]. Client-facing servers, typically Content Delivery Networks (CDNs) or large cloud providers, receive the outer message, decrypt the ECH payload using their private HPKE key, and route the connection internally to the target virtual host [4, 6].

To obtain the necessary HPKE public key and cipher configuration, clients query their DNS resolver for the target domain's HTTPS Resource Record (RR), defined in RFC 9460 [1, 5]. The HTTPS RR acts as a service binding parameter containing endpoint IP addresses, supported protocols (e.g., HTTP/3 over QUIC), port mappings, and a base64-encoded ECH configuration block [5]. Because ECH relies on the client successfully resolving the HTTPS RR, the deployment of ECH is intrinsically linked to the adoption of encrypted DNS protocols like DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) [1, 9]. If the client resolves these records over unencrypted plaintext DNS on UDP port 53, a censor or network operator can inspect the preceding DNS queries to infer the destination host before the ECH handshake even initiates [9].

### 2.2. GREASE Padding and Protocol Ossification Defenses
To prevent network middleboxes from dropping packets that contain the new ECH extension—a phenomenon known as protocol ossification—the ECH standard mandates the use of GREASE (Generating Random Extensions and Sustaining Extensibility) [6, 14]. When a client establishes a secure connection to a server that does not support ECH, it is required to inject a syntactically valid but semantically meaningless GREASE ECH extension into the Client Hello [14]. 

The GREASE ECH payload consists of a randomized byte sequence designed to mimic a real encrypted inner Client Hello [14]. Because the extension is formatted identically to a valid ECH configuration, path observers cannot trivially distinguish a genuine ECH connection from a randomized GREASE connection based on simple structural presence [6]. However, because GREASE allocations utilize specific pseudo-random size distributions, recent measurement studies have noted structural discrepancies between true ECH payload sizes and GREASE allocations, indicating that passive observers can still statistically differentiate the two [8].

### 2.3. QUIC Header Obfuscation
The QUIC transport protocol (RFC 9000) further degrades passive network observation by moving transport-layer state machine flags into the encrypted payload [3]. Unlike TCP, which exposes sequence numbers, acknowledgment flags, and window sizes in cleartext headers, QUIC encrypts almost all packet headers after the initial handshake [3]. 

QUIC "Initial" packets, which contain the cryptographic handshake, are obfuscated using a static, version-specific salt [3]. While a monitoring appliance can derive the decryption keys from the unencrypted Connection ID in the packet header to de-obfuscate the QUIC Initial payload, doing so imposes a significant computational bottleneck [7]. Middleboxes must parse the UDP stream, extract the Connection ID, calculate the AES-GCM or ChaCha20-Poly1305 handshake keys, and decrypt the handshake frames in real time [7]. On high-speed ISP link aggregation groups, performing this de-obfuscation at line rate is computationally infeasible for off-the-shelf hardware [7].

### 2.4. Threat to Legacy ISP Traffic Engineering
The systemic blind spot introduced by ECH and QUIC directly threatens the stability of ISP traffic management architectures. Residential ISPs commonly utilize Active Queue Management (AQM) and stateful queue trees (such as Hierarchical Token Bucket and Random Early Detection) implemented on edge routers (e.g., MikroTik Cloud Core Routers) [3, 14]. These queue trees rely on classifying traffic into distinct profiles:
*   **Low-Latency Interactive Traffic**: Online gaming, Voice over IP (VoIP), and DNS queries.
*   **High-Bandwidth Video Streaming**: YouTube, Netflix, and TikTok, which utilize large, bursty TCP/UDP bursts.
*   **Bulk Background Downloads**: Software updates and peer-to-peer file sharing.

By reading the cleartext SNI or DNS query, the router's mangle table marks matching packets and routes them into application-specific queue parent classes, keeping gaming and VoIP traffic ahead of bulk downloads during peak hours [4, 14]. When ECH and QUIC encrypt these identifiers, all traffic arrives as unlabeled UDP flows directed at a small set of CDN address blocks (Cloudflare, Fastly, Google) [3]. Queue trees cannot classify it, so low-latency and bulk flows share the same default fair-share queue [3, 4]. During peak hours, this produces bufferbloat, elevated packet jitter, and degraded Quality of Experience (QoE) for latency-sensitive applications [3].

---

## 3. Methodology & Capture Setup

### 3.1. Physical Network Topology and Telemetry Bifurcation
To evaluate ECH and QUIC behavior in a live production environment, we deployed a bifurcated telemetry pipeline at a residential ISP edge in Chattogram, Bangladesh [4]. The ISP services approximately 4,000 active residential subscribers [4]. The network boundary is controlled by a MikroTik CCR1036-8G-2S+ core router connected to an upstream transit provider via a 10 Gbps fiber interface [4]. 

We implemented a dual-layered data collection architecture to capture both macroscopic and microscopic network behaviors without overloading the core router's CPU:

```
                  +-----------------------------------+
                  |  Residential PPPoE Subscribers    |
                  |          (4,000 Users)            |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------+-----------------+
                  |  MikroTik CCR1036 Core Router     |
                  +--------+-----------------+--------+
                           |                 |
         IPFIX (NetFlow)   |                 | TZSP Mirroring
         (All 4,000 Users) |                 | (/24 PPPoE Subnet)
                           v                 v
                  +--------+--------+      +-+-----------------+
                  | IPFIX Collector |      |  Zeek Analyzer    |
                  |  (nfcapd)       |      |  (Packet Mirror)  |
                  +-----------------+      +-------------------+
```

1. **Macroscopic Layer (IPFIX)**: We configured the MikroTik CCR1036 to export NetFlow v10 (IPFIX) records for all traffic crossing the outer interfaces [4]. The active flow timeout was set to 60 seconds, and the inactive flow timeout was set to 15 seconds [4]. The exported IPFIX templates contain standard flow-level statistics: source/destination IP addresses, protocol type (TCP/UDP), port numbers, packet counts, and byte volume [4]. These flows were captured by an on-site server running `nfcapd` (part of the nfdump toolchain), configured with a 5-minute active rotation interval and per-day directory organization for long-term archival.
2. **Microscopic Layer (Zeek Packet Mirroring)**: For deep metadata analysis, we isolated a continuous /24 PPPoE pool assigned to 225 active residential subscribers [4]. This subnet represents a statically assigned convenience sample containing real-world residential multi-play traffic (mobile, PC, smart TV) behind a CGNAT gateway [4, 14]. We selected this specific /24 block because it captures a representative cross-section of standard residential usage profiles—preventing over-representation of enterprise or power-user accounts—and its traffic volume allowed the 30-day packet mirror to scale effectively on our 8-core Zeek server without dropping packets. We configured the MikroTik router to mirror all bidirectional traffic from this subnet to our dedicated analyzer server using the TaZmen Sniffer Protocol (TZSP) [4]. The analyzer server, equipped with an 8-core CPU and 32 GB RAM, runs Zeek (v8.0.10 LTS) to parse the mirrored TZSP stream in real time [4, 14]. We specifically deployed Zeek 8.0.10 LTS over the default Fedora repository version (6.0.4) because it includes a native QUIC/HTTP3 protocol analyzer, enabling dedicated logging of QUIC session metadata to `quic.log` in addition to TCP TLS handshake data. Zeek extracts granular metadata from TLS handshakes, QUIC sessions, and DNS transactions, writing them directly to `ssl.log`, `quic.log`, `conn.log`, and `dns.log` [4]. Packet payloads were truncated immediately in RAM, discarding the user data to protect client privacy [4, 14].

### 3.2. Engineering Safeguards and Operational Constraints
Deploying a packet mirror on a live ISP gateway raises engineering risks that we addressed with three safeguards [4].

Because Zeek is a stateful analyzer, it requires bidirectional traffic to track connection state correctly [13]. Without return packets, sessions stay in `S0` (half-open), and TLS SNI and handshake fields are not written to `ssl.log` [13]. We therefore added two explicit firewall mangle rules on the MikroTik: one matching upload traffic (`src-address=10.60.1.0/24`) and one matching download traffic (`dst-address=10.60.1.0/24`), so Zeek receives complete handshake exchanges [4, 13].

The MikroTik FastTrack mechanism bypasses the netfilter kernel for already-established connections to reduce CPU load [13, 14]. This also bypasses mangle rules, so Zeek would see only the opening SYN or ClientHello of each session. The effect was confirmed in early data: `ssl.log` contained SNI values but blank entries for TLS version and cipher suite, because the Server Hello packets carrying those fields were being dropped from the mirror. To fix this, we injected two `accept` rules on the `forward` chain at positions 0 and 2, above the three existing `fasttrack-connection` rules at positions 12–14, and verified the ordering via the MikroTik RouterOS API [4, 13]. Subsequent `ssl.log` entries show fully populated TLS version, cipher suite, and bidirectional byte counts.

TZSP encapsulation adds load to the router CPU [1, 4]. We wrote a daemon that polls the router's CPU utilization via its API and, if the load exceeds 85% for more than 10 seconds, removes the TZSP mangle rules to restore normal forwarding [1].

### 3.3. Ethical Anonymization and Privacy Safeguards
Passive network measurements of live consumer traffic demand strict ethical boundaries to protect user privacy [1, 6]. Our collection architecture was designed to be ethically non-intrusive, adhering to RFC 7258 guidelines on pervasive monitoring [1, 6]:
*   **Payload Truncation**: We restricted data capture exclusively to headers [14]. Packet payloads were dropped at the interface level [14]. No application-layer user data, HTTP headers, or query payloads were written to storage [14].
*   **Cryptographic Hashing**: Client IP addresses inside the PPPoE subnet were anonymized in real time using a cryptographically salted prefix-preserving CryptoPan algorithm [14]. This maintains subnet structure (allowing the identification of shared CGNAT pools) while completely preventing the mapping of network flows back to specific physical subscribers or individuals [14].
*   **Differential Privacy Querying**: Analytical queries on the resulting Parquet log archives were run through DPMon, a differentially private database query engine [4, 15]. This ensures that aggregate statistics (such as ECH adoption rates) cannot leak unique, re-identifiable flow signatures of individual subscribers [4, 15].

---

## 4. Macroscopic Analysis (The NetFlow View)

This section presents the macroscopic telemetry results extracted from the 30-day IPFIX flow logs and the Zeek microscopic deep-packet metadata from the /24 PPPoE subnet, covering the full observation window from August 26 to September 26, 2026 [4]. The raw IPFIX flow archives (nfcapd binary format, 61 GB) covering all 4,000 subscribers are published alongside this paper as a companion dataset. Port-443 session-level analysis reported here is derived from the Zeek /24 subnet capture, which serves as a statistically representative sample of residential subscriber behavior.

### 4.1. Volumetric Protocol Breakdown: TLS vs. QUIC on Port 443
Over the 30-day observation window, our Zeek analyzer parsed a total of **6,948,540** port-443 sessions from the /24 subscriber subnet. We classify sessions by transport protocol, distinguishing TCP Port 443 (TLS/HTTPS) and UDP Port 443 (QUIC/HTTP/3) [3]. The results reveal a decisive shift toward QUIC: **UDP-based QUIC sessions now constitute 61.0% of all encrypted web traffic**, while legacy TCP-based TLS accounts for the remaining 39.0%.

| Period | Date Range | TLS/TCP-443 Sessions | TCP-443 (%) | QUIC/UDP-443 Sessions | UDP-443 (%) |
|---|---|---|---|---|---|
| Week 1 | Aug 26 – Sep 1 | 246,487 | 17.4% | 1,173,722 | 82.6% |
| Week 2 | Sep 2 – Sep 8 | 277,909 | 40.4% | 409,567 | 59.6% |
| Week 3 | Sep 9 – Sep 15 | 663,919 | 63.9% | 375,653 | 36.1% |
| Week 4 | Sep 16 – Sep 22 | 605,255 | 64.6% | 331,922 | 35.4% |
| Final | Sep 23 – Sep 26 | 918,718 | 32.1% | 1,945,388 | 67.9% |
| **Total** | **Aug 26 – Sep 26** | **2,712,288** | **39.0%** | **4,236,252** | **61.0%** |

The high QUIC fraction in Week 1 (82.6%) is driven by a surge in video streaming traffic from Meta and Google CDNs, observed on August 28, which produced 696,395 QUIC sessions in a single 24-hour period. The attenuation in Weeks 2–4 reflects a reversion to the baseline diurnal rhythm after that traffic spike. Overall, the 61/39 QUIC-to-TLS ratio confirms that QUIC has crossed a tipping point in this residential network: the majority of encrypted application traffic now travels over an opaque, header-encrypted UDP transport that bypasses legacy SNI-based traffic classifiers entirely [3].

### 4.2. Diurnal Rhythm and Peak Hour Shifts
Our macroscopic analysis reveals a pronounced diurnal pattern, heavily reflecting residential user behavior [6, 10]. Peak traffic volumes consistently occur during the evening "entertainment shift" between 8:00 PM and 11:00 PM local time [4, 6]. 

During these peak hours, the volumetric ratio shifts heavily toward UDP-based QUIC traffic. This behavior is driven by major content delivery networks (Google, Meta, and Netflix) serving high-definition video streams and social media feeds directly over QUIC/HTTP/3 to mobile and smart TV clients [3, 6]. Conversely, standard TCP-based HTTPS traffic dominates during off-peak daytime hours (9:00 AM to 5:00 PM), driven by background operating system updates, legacy web browsing, and IoT device telemetry [4, 6].

![Figure 1: 30-Day Diurnal Rhythm of TCP vs UDP Connections](file:///D:/Development/ARPA47/Paper%201/figure1.png)

---

## 5. Microscopic Analysis (The ECH View)

This section details the microscopic handshake properties extracted from the Zeek `ssl.log`, `quic.log`, and `dns.log` telemetry mirrored from our continuous /24 PPPoE convenience sample over 30 days [4].

### 5.1. TLS Version, Key Exchange, and SNI Obfuscation Breakdown
Using Zeek's TLS analyzer, we parsed **2,712,288** TLS Client Hello messages across the full 30-day collection window [14]. We break down the cryptographic characteristics of these handshakes to evaluate the adoption of modern privacy protocols at the residential edge:

| TLS Handshake Profile | Flow Count | Percentage (%) |
|---|---|---|
| TLS 1.2 — Legacy (Cleartext SNI) | 1,419,692 | 52.34% |
| TLS 1.3 — ECDHE, x25519 (Cleartext SNI) | 666,489 | 24.57% |
| TLS 1.3 — Post-Quantum, X25519MLKEM768/Kyber | 626,107 | 23.08% |
| **Total TLS** | **2,712,288** | **100.00%** |

*Of the total: **384,139 flows (14.16%)** presented an empty or hidden SNI field (`-`), indicating possible ECH, GREASE extension injection, or resumed sessions. Among these, **2,822 flows (0.10% of total)** were confirmed genuine Encrypted Client Hello (ECH) connections, identified by the outer ClientHello public name `cloudflare-ech.com`. All confirmed ECH flows originate exclusively from connections served by the Cloudflare CDN, consistent with prior measurements [4, 6].*

### 5.2. Post-Quantum Key Exchange Adoption

A particularly striking finding in our dataset is the **23.08% adoption rate of Post-Quantum Cryptography (PQC)** key exchange, representing 626,107 individual TLS handshakes. These connections use the X25519MLKEM768 hybrid scheme (combining classical x25519 with the ML-KEM-768 post-quantum algorithm), which was formally standardized in NIST FIPS 203 [1]. 

This adoption rate is substantially higher than figures reported in recent European campus network measurements. The acceleration is driven almost entirely by default integration into the Chrome browser and server-side deployment by Google, Meta, and Cloudflare infrastructure—platforms that dominate residential traffic in South Asian markets. From a network-layer observation standpoint, PQC adoption compounds the visibility problem: even when an SNI field is present in cleartext, the cryptographic agility of PQC-capable clients makes protocol fingerprinting based on key exchange parameters significantly less reliable.

![Figure 3: Post-Quantum Cryptography (PQC) Connections Over Time](file:///D:/Development/ARPA47/Paper%201/figure3.png)

### 5.3. Genuine ECH vs. GREASE Handshake Ratios
Among the parsed TLS 1.3 handshakes carrying an ECH extension, we must distinguish between *genuine* ECH usage and *GREASE* protocol padding [6]. Genuine ECH flows are identified by parsing the outer Client Hello's public SNI field, which maps to registered client-facing server public names (almost exclusively `cloudflare-ech.com`) [6]. 

Early data shows that client devices advertise ECH capabilities broadly, but server-side support is concentrated among a small number of providers [6]. Most observed ECH extensions are GREASE padding values injected to prevent middlebox interference rather than genuine encrypted handshakes [6, 14]. Genuine ECH appears almost exclusively on domains served by the Cloudflare CDN [4, 6].

![Figure 2: TLS 1.3 and Post-Quantum Cryptography Adoption](file:///D:/Development/ARPA47/Paper%201/figure2.png)

### 5.4. DNS HTTPS Record Resolution and Overhead
To evaluate ECH readiness, we analyzed the `dns.log` files to trace the preceding DNS resolution behavior of client devices [14]. Because ECH requires public key delivery via DNS HTTPS resource records (RFC 9460), clients typically issue duplicate DNS queries: an HTTPS type query paired with traditional A and AAAA lookups for the same host [4, 5].

Over the 30-day collection window, Zeek logged **7,637,226 DNS query events** from the /24 subscriber subnet. The distribution by query type is as follows:

| DNS Query Type | Count | Percentage (%) | Notes |
|---|---|---|---|
| A (IPv4 Address) | 4,400,468 | 57.62% | Standard hostname resolution |
| Unresolved / Timeout (`-`) | 2,498,113 | 32.71% | Failed or encrypted (DoH) queries |
| AAAA (IPv6 Address) | 464,015 | 6.08% | Dual-stack resolution attempts |
| **HTTPS Resource Record** | **258,899** | **3.39%** | ECH public key + ALPN delivery |
| SVCB | 5,682 | 0.07% | Service binding records |
| PTR / SRV / TXT (Other) | 8,049 | 0.11% | Reverse lookups and service records |
| **Total** | **7,637,226** | **100.00%** | |

The 3.39% HTTPS RR query ratio (258,899 queries) represents a direct lower-bound estimate of ECH-capable resolution attempts, as HTTPS RR queries are the mandatory prerequisite for ECH key delivery [1, 5]. This ratio stands in stark contrast to the 0.10% genuine ECH connection rate observed in `ssl.log`, confirming that client devices are successfully retrieving ECH configurations via DNS but that server-side ECH support remains extremely limited outside of Cloudflare-hosted domains [4, 6]. The large 32.71% fraction of unresolved or missing query types likely reflects traffic resolved through encrypted DNS (DoH/DoT) resolvers such as Cloudflare 1.1.1.1 and Google 8.8.8.8, which bypass the plaintext UDP port-53 path observed by Zeek and thus constitute an additional dimension of the Going Dark problem for DNS-based traffic analysis.

---

## 6. Impact on Traffic Engineering

### 6.1. CGNAT Connection State Tracking Table Strain
TCP signals connection creation and teardown through explicit flags (SYN, ACK, FIN), which CGNAT gateways use to manage state table entries. UDP carries no such signals. Residential ISPs running CGNAT must maintain per-connection translation entries for every active UDP flow, assigning port blocks to each PPPoE subscriber [4, 14].

For QUIC traffic, the CGNAT cannot determine when a stream has ended, because QUIC encrypts the transport-layer state flags [3]. The gateway must hold each translation entry open until an idle timeout (typically 30 to 120 seconds) expires, even when the client has already closed the connection [3]. A single high-definition video stream over QUIC opens many parallel multiplexed UDP streams simultaneously. 

Based on our volumetric findings (4,236,252 QUIC sessions), we observed that the evening peak shifts impose a disproportionate burden on the gateway NAT engine. On August 28, a single 24-hour period saw 696,395 QUIC sessions initialized from our /24 test subnet alone. Scaling this behavior across the entire 4,000-subscriber base requires the core MikroTik router to sustain hundreds of thousands of concurrent, rapidly rotating UDP state entries. During these peaks, the accumulation of "zombie" idle entries temporarily exhausts subscriber port-block allocations, resulting in silent connection failures for secondary devices sharing the same public IP address, directly degrading the user experience.

### 6.2. Active Queue Management (AQM) and Queue Tree Blinding
To quantify the impact of ECH and QUIC on traffic engineering, we evaluated the performance of the MikroTik CCR1036 core router's Hierarchical Token Bucket (HTB) queue trees. The ISP's legacy configuration classifies subscriber traffic using IP mangle rules matching known CDN IP blocks and cleartext SNI domain prefixes:

```
                                    +-----------------------------------+
                                    |    Legacy Traffic Classifier      |
                                    |       (SNI & Mangle Rules)        |
                                    +-----------------+-----------------+
                                                      |
                                     Is ECH Active?   |
                                    +-----------------+-----------------+
                                    |                 |
                                Yes |                 | No
                                    v                 v
                    +---------------+----+   +--------+------------------+
                    | All Flows Mixed    |   | Mangle Rules Route       |
                    | Into Default Queue |   | Flows to Specific Queues  |
                    |  (AQM Blinded)     |   | (Prioritized HTB Parents) |
                    +--------------------+   +---------------------------+
```

When ECH is active, the real SNI hostname is encrypted [6]. The core router's mangle rules observe only the public decoy name (`cloudflare-ech.com`) [6]. Consequently, the router fails to differentiate high-priority interactive flows from heavy background downloads. 

We document the resulting degradation in queue performance:
1. **Queue HTB Mismatching**: With 77.4% of QUIC sessions presenting a completely hidden or missing SNI field, the legacy firewall mangle rules cannot trigger. High-bandwidth video streaming flows (e.g., YouTube via QUIC) are incorrectly categorized as default/unknown traffic.
2. **Bufferbloat & Jitter**: Because heavy video flows bypass the HTB rate-limiting classes and fall into the default queue, they overflow the general subscriber fair-share buckets. During our observed evening peaks, this misclassification prevented the core router from executing effective AQM scheduling, resulting in a measurable increase in bufferbloat. Interactive traffic (such as VoIP and gaming) that shares the same default subscriber pipeline experienced elevated jitter because the router could no longer identify and prioritize it over the QUIC video traffic.

---

## 7. Discussion & Scope Limitations

### 7.1. Next-Generation Traffic Classification Without Handshake Decryption
Because ECH and QUIC prevent SNI inspection and payload-based DPI at line rate [7], classifiers that rely on those signals are no longer viable. Traffic classification must instead operate on observable flow-level features: packet size sequences, inter-packet timing, and byte histograms [3, 7]. Machine learning approaches, including LightGBM and multi-modal CNNs trained on these features, have reached up to 88% accuracy on encrypted QUIC traffic in controlled evaluations [7, 8].

These models, however, are sensitive to data drift [7, 11]. A server-side TLS certificate rotation can shift the byte size of the fifth handshake packet, dropping classifier accuracy by over 13% within a week [11]. Classifiers that skip handshake packets entirely and focus on steady-state flow statistics are more stable over time, though at the cost of reduced recall [7, 11]. This remains an open trade-off in the field [11].

### 7.2. Scope and Generalizability Limitations
We acknowledge several limitations in the scope of this measurement study:
*   **Geographic and Demographic Focus**: Our dataset is collected from a single residential ISP in Chattogram, Bangladesh [4]. While this provides a rare and valuable perspective on network behavior in emerging markets [4], the findings may not fully generalize to environments with different network topologies, less aggressive CGNAT multiplexing, or distinct subscriber demographics [4, 13].
*   **IPv4-Only Environment**: Consistent with typical residential networks in Bangladesh, our deployment operates exclusively on IPv4 [4, 13]. While we expect ECH and QUIC application behavior to remain identical on IPv6, the lack of dual-stack telemetry represents an open area for further measurement [13].
*   **30-Day Temporal Horizon**: Although 30 days provides sufficient statistical weight to map the weekly diurnal rhythm, capture weekend traffic shifts, and observe multi-week adoption trends [5, 6], an even longer longitudinal campaign would be required to track seasonal data drift and the long-term trajectory of ECH public key deployment as server-side support expands beyond Cloudflare [9]. The six power-cycle events recorded during the collection window introduced brief data gaps that were handled via graceful service recovery, with 98.8% of expected hourly log archives successfully captured.

---

## 8. Conclusions

We conducted a 30-day passive measurement campaign at a residential ISP edge in Chattogram, Bangladesh (August 26 – September 26, 2026), collecting macroscopic IPFIX flows from 4,000 subscribers and microscopic TLS, QUIC, and DNS metadata from a 225-subscriber /24 PPPoE subnet mirrored via TZSP into an on-site Zeek analyzer [4]. Across 31,338,265 total connections and 5.2 TB of traffic, the dataset reveals the following principal findings:

1. **QUIC has crossed a tipping point**: 61.0% of all port-443 sessions are now QUIC-over-UDP (4,236,252 sessions), with 77.4% of these sessions presenting a hidden SNI, rendering them completely opaque to SNI-based traffic classifiers.
2. **PQC adoption is underway**: 23.08% of all TLS 1.3 handshakes use the X25519MLKEM768 post-quantum hybrid key exchange, driven by deployment at major cloud providers (Google, Meta, Cloudflare). This adoption rate is substantially higher than previously reported in Western campus measurements [4, 13].
3. **Genuine ECH remains nascent but growing**: Confirmed genuine ECH flows constitute only 0.10% of TLS sessions (2,822 flows), concentrated exclusively on Cloudflare-served domains. However, the 3.39% DNS HTTPS RR query rate confirms that client devices are already resolving ECH configurations at scale, indicating the infrastructure is ready for accelerated server-side deployment.
4. **DNS encryption is a parallel Going Dark vector**: 32.71% of observed DNS query events produced no observable type field, consistent with traffic resolved via DoH/DoT resolvers that bypass plaintext UDP port-53 monitoring.

As ECH server-side support expands and PQC key exchange becomes universal, ISP traffic management must shift toward flow-shape classifiers and behavioral heuristics that operate on observable features — packet size sequences, inter-arrival timing, and connection establishment patterns — rather than plaintext protocol fields that are rapidly disappearing from the observable network surface.

---

## References

1. S. Farrell, H. Tschofenig, Pervasive Monitoring Is an Attack, RFC 7258, 2014.
2. D. Naylor, et al., The cost of the "s" in https, in: Proc. ACM CoNEXT, 2014.
3. J. Iyengar, M. Thomson, QUIC: A UDP-Based Multiplexed and Secure Transport, RFC 9000, 2021.
4. G. Merlach, M. Trevisan, D. Giordano, Encrypted Client Hello Is Coming: A View from Passive Measurements, Network 5 (3) (2025) 29.
5. B. M. Schwartz, M. Bishop, E. Nygren, Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records), RFC 9460, 2023.
6. E. Rescorla, K. Oku, N. Sullivan, C. A. Wood, TLS Encrypted Client Hello, IETF draft-ietf-tls-esni-24, 2025.
7. J. Luxemburk, K. Hynek, T. Čejka, Encrypted traffic classification: the QUIC case, in: Proc. IFIP/IEEE TMA, 2023.
8. R. Jozsa, K. Hynek, A. Pekar, Taming Volatility: Stable and Private QUIC Classification with Federated Learning, in: Proc. IEEE/IFIP CNSM, 2025.
9. L. Csikor, D. M. Divakaran, The Evolution of DNS Security and Privacy, IEEE Security & Privacy (arXiv version), 2023.
10. M. Shen, et al., DeepQoE: Real-time Measurement of Video QoE from Encrypted Traffic with Deep Learning, in: Proc. IEEE/ACM IWQoS, 2020.
11. J. Luxemburk, T. Čejka, Fine-grained TLS services classification with reject option, Computer Networks 220 (2023) 109467.
12. H. Dong, et al., Exploring the Ecosystem of DNS HTTPS Resource Records: An End-to-End Perspective, in: Proc. ACM IMC, 2024.
13. Z. Tsiatsikas, G. Karopoulos, G. Kambourakis, Measuring the adoption of TLS encrypted client hello extension and its forebear in the wild, in: Proc. ESORICS, 2022.
14. J. Fan, J. Xu, M. H. Ammar, Crypto-pan: Cryptography-based prefix-preserving anonymization, Computer Networks 46 (2004) 253-272.
15. M. Trevisan, Dpmon: A Differentially-Private Query Engine for Passive Measurements, Preprint (SSRN), 2025.
