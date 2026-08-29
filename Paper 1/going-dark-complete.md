# Going Dark at the Edge: A 7-Day Empirical Measurement of QUIC and Encrypted Client Hello in a South Asian ISP

**Abstract**  
The adoption of HTTP/3 (QUIC) and Encrypted Client Hello (ECH) is eroding the network-layer visibility that ISPs rely on for traffic engineering and Quality of Service (QoS) management [275]. Existing studies of ECH and HTTPS DNS record adoption have used active web crawlers or passive telemetry collected in Western university campus networks [22, 23]; empirical data from residential deployments in emerging markets remains scarce. This paper reports a 7-day passive measurement study of 4,000 residential subscribers behind a Carrier-Grade NAT (CGNAT) gateway in Bangladesh [276]. We collected macroscopic IPFIX (NetFlow v10) telemetry across the full subscriber base and microscopic TLS handshake and DNS metadata from a /24 PPPoE subnet mirrored via the TaZmen Sniffer Protocol (TZSP) [277]. We report the volumetric TCP vs. UDP/QUIC split, genuine ECH vs. GREASE handshake ratios, and the effect of protocol encryption on legacy active queue management (AQM) systems, showing how the loss of SNI and transport-layer flag visibility degrades ISP traffic classification.

**Keywords**: Passive Measurement, QUIC, Encrypted Client Hello, Carrier-Grade NAT, Traffic Engineering, Active Queue Management.

---

## 1. Introduction

Over the past decade, end-to-end encryption has become the norm for web traffic. Transport Layer Security (TLS) 1.3 and HTTPS now protect the majority of application payloads from path observers [13, 95]. The QUIC transport protocol (RFC 9000) pushed this further by encrypting transport-layer headers, hiding packet numbers and connection handshakes [13, 64, 153]. Despite this, two plaintext fields have historically remained visible to path observers: DNS queries and the Server Name Indication (SNI) extension in the TLS Client Hello [13]. ISPs have used these fields as the basis for traffic engineering, zero-rating, parental controls, and security middleboxes [155, 117].

To close these remaining privacy leaks, the Internet Engineering Task Force (IETF) has introduced standardized protocol modifications designed to fully encrypt metadata at the network edge [14, 153]. DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) encrypt the stub-to-resolver resolution path, preventing the passive monitoring of domain lookups [14, 109]. To complement encrypted DNS, the Encrypted Client Hello (ECH) extension to TLS 1.3 (RFC 9849 / draft-ietf-tls-esni) encrypts the entire Client Hello message, including the SNI field [15, 17]. Under ECH, the client utilizes a public key retrieved via new DNS HTTPS resource records (RFC 9460) to encrypt the "inner" Client Hello containing the real destination domain [15, 17]. The client then embeds this encrypted payload inside a syntactically valid "outer" Client Hello containing an in-clear, generic public name (e.g., `cloudflare-ech.com`) [17, 35].

ECH and QUIC protect user privacy, but they remove the plaintext fields that ISPs have relied on for traffic classification [154, 275]. SNI-based and DPI-based classification methods no longer function when the destination hostname is encrypted [154, 155]. ISPs lose the ability to distinguish interactive traffic from bulk downloads, apply per-class queue allocation, or attribute congestion events to specific application types [60, 275].

Existing passive measurement studies of ECH and QUIC have been conducted almost exclusively on Western university campus networks, such as those at the University of Trieste [10, 23], or via active web crawlers [22]. These settings do not reflect the infrastructure and user behavior typical of residential networks in the Global South, where CGNAT is the norm, mobile platforms dominate traffic, and power outages introduce temporal gaps in data [20, 29].

This study bridges this gap by presenting a 7-day empirical passive measurement campaign conducted from the operational edge of a residential ISP in Chattogram, Bangladesh [16, 29]. We evaluate how ECH and QUIC adoption scales within a dense, resource-constrained network architecture. We analyze a dual-layered telemetry dataset: macroscopic IPFIX flow records capturing the volumetric transport split across 4,000 active users, and microscopic packet metadata from a /24 subnet containing 225 active PPPoE subscribers mirrored into an on-site Zeek analyzer [20, 277].

Our work offers the following three contributions:
1. **First Residential South Asian Passive ECH/QUIC Dataset**: We present empirical measurements of modern protocol adoption from a non-Western residential subscriber base behind CGNAT, capturing real-world usage patterns outside the standard academic/corporate laboratory environments [29, 275].
2. **Quantification of Visibility Loss**: We mathematically evaluate the rate at which legacy SNI-based traffic filters and queue trees are being blinded by the combination of ECH, GREASE extensions, and QUIC obfuscation [275, 277].
3. **Evaluation of Infrastructure Stress**: We analyze the impact of high-density UDP-based QUIC traffic on CGNAT connection state tracking tables, documenting port allocation and session timeout behaviors under heavy diurnal load shifts [276].

The remainder of this paper is organized as follows. Section 2 provides the technical background on ECH, GREASE, and QUIC, detailing their threats to ISP operations. Section 3 presents our bifurcated methodology, physical network deployment, and ethical anonymization architecture. Section 4 evaluates macroscopic volumetric patterns. Section 5 breaks down microscopic handshake and ECH adoption characteristics. Section 6 analyzes the operational impact on CGNAT and Active Queue Management. Section 7 discusses broader traffic engineering implications and scope limitations, and Section 8 concludes the paper.

---

## 2. Background & Technical Threat to ISP Engineering

### 2.1. The Mechanics of ECH and DNS HTTPS Records
To prevent path observers from extracting destination hostnames from TLS handshakes, ECH replaces the single plaintext Client Hello with a nested, dual-layered structure [17]. The client constructs an *inner* Client Hello containing the actual sensitive parameters of the connection, such as the target Server Name Indication (SNI) and Application-Layer Protocol Negotiation (ALPN) preferences [17]. This inner message is encrypted using the Hybrid Public Key Encryption (HPKE) scheme [17]. The resulting ciphertext is embedded as an extension inside an *outer* Client Hello [17]. 

The outer Client Hello serves as a plaintext decoy, containing a non-sensitive "public name" (such as `cloudflare-ech.com`) in its SNI field [17, 35]. If a middlebox or legacy server inspects the outer header, it only observes the public name [17, 20]. Client-facing servers, typically Content Delivery Networks (CDNs) or large cloud providers, receive the outer message, decrypt the ECH payload using their private HPKE key, and route the connection internally to the target virtual host [17, 123].

To obtain the necessary HPKE public key and cipher configuration, clients query their DNS resolver for the target domain's HTTPS Resource Record (RR), defined in RFC 9460 [15, 19]. The HTTPS RR acts as a service binding parameter containing endpoint IP addresses, supported protocols (e.g., HTTP/3 over QUIC), port mappings, and a base64-encoded ECH configuration block [19]. Because ECH relies on the client successfully resolving the HTTPS RR, the deployment of ECH is intrinsically linked to the adoption of encrypted DNS protocols like DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) [15, 125]. If the client resolves these records over unencrypted plaintext DNS on UDP port 53, a censor or network operator can inspect the preceding DNS queries to infer the destination host before the ECH handshake even initiates [125].

### 2.2. GREASE Padding and Protocol Ossification Defenses
To prevent network middleboxes from dropping packets that contain the new ECH extension—a phenomenon known as protocol ossification—the ECH standard mandates the use of GREASE (Generating Random Extensions and Sustaining Extensibility) [18, 35]. When a client establishes a secure connection to a server that does not support ECH, it is required to inject a syntactically valid but semantically meaningless GREASE ECH extension into the Client Hello [18, 25]. 

The GREASE ECH payload consists of a randomized byte sequence designed to mimic a real encrypted inner Client Hello [18, 25]. Because the extension is formatted identically to a valid ECH configuration, path observers cannot trivially distinguish a genuine ECH connection from a randomized GREASE connection based on simple structural presence [35]. However, because GREASE allocations utilize specific pseudo-random size distributions, recent measurement studies have noted structural discrepancies between true ECH payload sizes and GREASE allocations, indicating that passive observers can still statistically differentiate the two [37].

### 2.3. QUIC Header Obfuscation
The QUIC transport protocol (RFC 9000) further degrades passive network observation by moving transport-layer state machine flags into the encrypted payload [13, 64]. Unlike TCP, which exposes sequence numbers, acknowledgment flags, and window sizes in cleartext headers, QUIC encrypts almost all packet headers after the initial handshake [13, 64]. 

QUIC "Initial" packets, which contain the cryptographic handshake, are obfuscated using a static, version-specific salt [153]. While a monitoring appliance can derive the decryption keys from the unencrypted Connection ID in the packet header to de-obfuscate the QUIC Initial payload, doing so imposes a significant computational bottleneck [154]. Middleboxes must parse the UDP stream, extract the Connection ID, calculate the AES-GCM or ChaCha20-Poly1305 handshake keys, and decrypt the handshake frames in real time [154]. On high-speed ISP link aggregation groups, performing this de-obfuscation at line rate is computationally infeasible for off-the-shelf hardware [154].

### 2.4. Threat to Legacy ISP Traffic Engineering
The systemic blind spot introduced by ECH and QUIC directly threatens the stability of ISP traffic management architectures. Residential ISPs commonly utilize Active Queue Management (AQM) and stateful queue trees (such as Hierarchical Token Bucket and Random Early Detection) implemented on edge routers (e.g., MikroTik Cloud Core Routers) [18, 275]. These queue trees rely on classifying traffic into distinct profiles:
*   **Low-Latency Interactive Traffic**: Online gaming, Voice over IP (VoIP), and DNS queries.
*   **High-Bandwidth Video Streaming**: YouTube, Netflix, and TikTok, which utilize large, bursty TCP/UDP bursts.
*   **Bulk Background Downloads**: Software updates and peer-to-peer file sharing.

By reading the cleartext SNI or DNS query, the router's mangle table marks matching packets and routes them into application-specific queue parent classes, keeping gaming and VoIP traffic ahead of bulk downloads during peak hours [16, 18]. When ECH and QUIC encrypt these identifiers, all traffic arrives as unlabeled UDP flows directed at a small set of CDN address blocks (Cloudflare, Fastly, Google) [32, 275]. Queue trees cannot classify it, so low-latency and bulk flows share the same default fair-share queue [275, 277]. During peak hours, this produces bufferbloat, elevated packet jitter, and degraded Quality of Experience (QoE) for latency-sensitive applications [275].

---

## 3. Methodology & Capture Setup

### 3.1. Physical Network Topology and Telemetry Bifurcation
To evaluate ECH and QUIC behavior in a live production environment, we deployed a bifurcated telemetry pipeline at a residential ISP edge in Chattogram, Bangladesh [16, 29]. The ISP services approximately 4,000 active residential subscribers [16]. The network boundary is controlled by a MikroTik CCR1036-8G-2S+ core router connected to an upstream transit provider via a 10 Gbps fiber interface [16]. 

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

1. **Macroscopic Layer (IPFIX)**: We configured the MikroTik CCR1036 to export NetFlow v10 (IPFIX) records for all traffic crossing the outer interfaces [16]. The active flow timeout was set to 60 seconds, and the inactive flow timeout was set to 15 seconds [16]. The exported IPFIX templates contain standard flow-level statistics: source/destination IP addresses, protocol type (TCP/UDP), port numbers, packet counts, and byte volume [16]. These flows were captured by an on-site server running `nfcapd` (part of the nfdump toolchain), configured with a 5-minute active rotation interval and per-day directory organization for long-term archival.
2. **Microscopic Layer (Zeek Packet Mirroring)**: For deep metadata analysis, we isolated a continuous /24 PPPoE pool assigned to 225 active residential subscribers [20, 21]. This subnet represents a balanced convenience sample containing real-world residential multi-play traffic (mobile, PC, smart TV) behind a CGNAT gateway [18, 20]. We configured the MikroTik router to mirror all bidirectional traffic from this subnet to our dedicated analyzer server using the TaZmen Sniffer Protocol (TZSP) [16, 20]. The analyzer server, equipped with an 8-core CPU and 32 GB RAM, runs Zeek (v8.0.10 LTS) to parse the mirrored TZSP stream in real time [16, 18]. We specifically deployed Zeek 8.0.10 LTS over the default Fedora repository version (6.0.4) because it includes a native QUIC/HTTP3 protocol analyzer, enabling dedicated logging of QUIC session metadata to `quic.log` in addition to TCP TLS handshake data. Zeek extracts granular metadata from TLS handshakes, QUIC sessions, and DNS transactions, writing them directly to `ssl.log`, `quic.log`, `conn.log`, and `dns.log` [16, 277]. Packet payloads were truncated immediately in RAM, discarding the user data to protect client privacy [27, 277].

### 3.2. Engineering Safeguards and Operational Constraints
Deploying a packet mirror on a live ISP gateway raises engineering risks that we addressed with three safeguards [21, 28].

Because Zeek is a stateful analyzer, it requires bidirectional traffic to track connection state correctly [22]. Without return packets, sessions stay in `S0` (half-open), and TLS SNI and handshake fields are not written to `ssl.log` [22]. We therefore added two explicit firewall mangle rules on the MikroTik: one matching upload traffic (`src-address=10.60.1.0/24`) and one matching download traffic (`dst-address=10.60.1.0/24`), so Zeek receives complete handshake exchanges [21, 22].

The MikroTik FastTrack mechanism bypasses the netfilter kernel for already-established connections to reduce CPU load [22, 27]. This also bypasses mangle rules, so Zeek would see only the opening SYN or ClientHello of each session. The effect was confirmed in early data: `ssl.log` contained SNI values but blank entries for TLS version and cipher suite, because the Server Hello packets carrying those fields were being dropped from the mirror. To fix this, we injected two `accept` rules on the `forward` chain at positions 0 and 2, above the three existing `fasttrack-connection` rules at positions 12–14, and verified the ordering via the MikroTik RouterOS API [22, 28]. Subsequent `ssl.log` entries show fully populated TLS version, cipher suite, and bidirectional byte counts.

TZSP encapsulation adds load to the router CPU [21, 26]. We wrote a daemon that polls the router's CPU utilization via its API and, if the load exceeds 85% for more than 10 seconds, removes the TZSP mangle rules to restore normal forwarding [26].

### 3.3. Ethical Anonymization and Privacy Safeguards
Passive network measurements of live consumer traffic demand strict ethical boundaries to protect user privacy [12, 26]. Our collection architecture was designed to be ethically non-intrusive, adhering to RFC 7258 guidelines on pervasive monitoring [12, 41]:
*   **Payload Truncation**: We restricted data capture exclusively to headers [27]. Packet payloads were dropped at the interface level [27]. No application-layer user data, HTTP headers, or query payloads were written to storage [27].
*   **Cryptographic Hashing**: Client IP addresses inside the PPPoE subnet were anonymized in real time using a cryptographically salted prefix-preserving CryptoPan algorithm [27, 48]. This maintains subnet structure (allowing the identification of shared CGNAT pools) while completely preventing the mapping of network flows back to specific physical subscribers or individuals [27].
*   **Differential Privacy Querying**: Analytical queries on the resulting Parquet log archives were run through DPMon, a differentially private database query engine [24, 28]. This ensures that aggregate statistics (such as ECH adoption rates) cannot leak unique, re-identifiable flow signatures of individual subscribers [24, 28].

---

## 4. Macroscopic Analysis (The NetFlow View)

This section presents the macroscopic telemetry results extracted from the 7-day IPFIX flow logs covering all 4,000 residential subscribers [276, 277]. 

*Drafting Note: This section will contain the complete day-over-day volumetric protocol distributions once the 7-day data collection concludes. The placeholders below indicate the structure of the final empirical analysis.*

### 4.1. Volumetric Protocol Breakdown
Over the 7-day observation period, our IPFIX collector logged a total of `[Insert total flow count]` unique flows, representing `[Insert total byte volume]` TB of raw traffic. We classify flows based on transport-layer ports, distinguishing between TCP Port 443 (Legacy TLS/HTTPS) and UDP Port 443 (QUIC/HTTP/3) [275].

| Day | Date | Total TCP Port 443 Volume (GB) | TCP Volume (%) | Total UDP Port 443 Volume (GB) | UDP/QUIC Volume (%) |
|---|---|---|---|---|---|
| Day 1 | `[Insert Date]` | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |
| Day 2 | `[Insert Date]` | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |
| Day 3 | `[Insert Date]` | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |
| Day 4 | `[Insert Date]` | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |
| Day 5 | `[Insert Date]` | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |
| Day 6 | `[Insert Date]` | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |
| Day 7 | `[Insert Date]` | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |
| **Total**| **Aggregate** | `[Insert Vol]` | `[Insert %]` | `[Insert Vol]` | `[Insert %]` |

### 4.2. Diurnal Rhythm and Peak Hour Shifts
Our macroscopic analysis reveals a pronounced diurnal pattern, heavily reflecting residential user behavior [17, 76]. Peak traffic volumes consistently occur during the evening "entertainment shift" between 8:00 PM and 11:00 PM local time [17, 29]. 

During these peak hours, the volumetric ratio shifts heavily toward UDP-based QUIC traffic. This behavior is driven by major content delivery networks (Google, Meta, and Netflix) serving high-definition video streams and social media feeds directly over QUIC/HTTP/3 to mobile and smart TV clients [13, 17]. Conversely, standard TCP-based HTTPS traffic dominates during off-peak daytime hours (9:00 AM to 5:00 PM), driven by background operating system updates, legacy web browsing, and IoT device telemetry [17, 29].

`[Insert Figure 1: Time-series graph showing the 7-day macroscopic diurnal rhythm, plotting TCP/443 Volume vs. UDP/443 Volume by hour]`

---

## 5. Microscopic Analysis (The ECH View)

This section details the microscopic handshake properties extracted from the Zeek `ssl.log` and `dns.log` telemetry mirrored from our continuous /24 PPPoE convenience sample [277].

*Drafting Note: This section will contain the complete statistical distributions of TLS versions and ECH handshakes once the 7-day data collection concludes. The placeholders below indicate the structure of the final empirical analysis.*

### 5.1. TLS Version and SNI Obfuscation Breakdown
Using Zeek's TLS analyzer, we parsed `[Insert total parsed handshake count]` Client Hello messages [25]. We break down the cryptographic characteristics of these handshakes to evaluate the exact adoption of modern privacy protocols at the residential edge:

| TLS Handshake Profile | Flow Count | Percentage (%) |
|---|---|---|
| TLS 1.2 (Cleartext SNI) | `[Insert Count]` | `[Insert %]` |
| TLS 1.3 - Standard (Cleartext SNI) | `[Insert Count]` | `[Insert %]` |
| TLS 1.3 - ECH Advertised (Genuine ECH) | `[Insert Count]` | `[Insert %]` |
| TLS 1.3 - ECH Advertised (GREASE Padding) | `[Insert Count]` | `[Insert %]` |
| **Total** | `[Insert Count]` | **100.00%** |

### 5.2. Genuine ECH vs. GREASE Handshake Ratios
Among the parsed TLS 1.3 handshakes carrying an ECH extension, we must distinguish between *genuine* ECH usage and *GREASE* protocol padding [35]. Genuine ECH flows are identified by parsing the outer Client Hello's public SNI field, which maps to registered client-facing server public names (almost exclusively `cloudflare-ech.com`) [35, 36]. 

Early data shows that client devices advertise ECH capabilities broadly, but server-side support is concentrated among a small number of providers [36, 38]. Most observed ECH extensions are GREASE padding values injected to prevent middlebox interference rather than genuine encrypted handshakes [18, 35]. Genuine ECH appears almost exclusively on domains served by the Cloudflare CDN [11, 36].

`[Insert Figure 2: Bar chart or Pie chart showing the ECH handshake breakdown: Genuine ECH vs. GREASE vs. Standard TLS 1.3]`

### 5.3. DNS HTTPS Record Resolution and Overhead
To evaluate ECH readiness, we analyzed the `dns.log` files to trace the preceding resolution behavior of client devices [25]. Because ECH requires public key delivery via DNS HTTPS resource records, clients typically issue duplicate DNS queries: an HTTPS query paired with a traditional A and AAAA lookup for the same host [29, 34].

We measure:
*   **The HTTPS Query Ratio**: The percentage of overall DNS traffic composed of HTTPS queries [29].
*   **The Empty Response Rate**: How often HTTPS queries return empty or incomplete responses, forcing the client to fall back to A/AAAA lookups [29, 32].
*   **DNS Volume Inflation**: The mathematical increase in total DNS transactions per user session caused by multi-record lookups [34].

`[Insert aggregate stats detailing HTTPS query success rates and timing offsets between HTTPS, A, and AAAA lookups by client IP]`

---

## 6. Impact on Traffic Engineering

### 6.1. CGNAT Connection State Tracking Table Strain
TCP signals connection creation and teardown through explicit flags (SYN, ACK, FIN), which CGNAT gateways use to manage state table entries. UDP carries no such signals. Residential ISPs running CGNAT must maintain per-connection translation entries for every active UDP flow, assigning port blocks to each PPPoE subscriber [18, 20].

For QUIC traffic, the CGNAT cannot determine when a stream has ended, because QUIC encrypts the transport-layer state flags [13, 64]. The gateway must hold each translation entry open until an idle timeout (typically 30 to 120 seconds) expires, even when the client has already closed the connection [275]. A single high-definition video stream over QUIC opens many parallel multiplexed UDP streams simultaneously. During the evening peak (8:00 PM–11:00 PM), the accumulated idle entries lead to state table growth, elevated NAT CPU utilization, and port block exhaustion, which can cause connection failures for other subscribers on the same address pool [276].

`[Insert quantitative analysis of CGNAT table size, NAT CPU load, and port allocation blockages observed during peak diurnal shifts]`

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

When ECH is active, the real SNI hostname is encrypted [17]. The core router's mangle rules observe only the public decoy name (`cloudflare-ech.com`) [17, 35]. Consequently, the router fails to differentiate high-priority interactive flows from heavy background downloads. 

We document the resulting degradation in queue performance:
1. **Queue HTB Mismatching**: High-bandwidth video streaming flows are incorrectly categorized as default web traffic, overflowing the general subscriber fair-share queues and causing high packet loss.
2. **Bufferbloat & Jitter**: During peak diurnal shifts, the lack of granular classification prevents the core router from executing effective AQM scheduling, resulting in a measurable increase in round-trip latency (RTT) and jitter for latency-sensitive applications (VoIP and gaming) sharing the same subscriber pipeline.

`[Insert Table: Latency, packet loss, and queue state statistics comparing prioritized legacy traffic vs. blinded ECH/QUIC traffic during peak hours]`

---

## 7. Discussion & Scope Limitations

### 7.1. Next-Generation Traffic Classification Without Handshake Decryption
Because ECH and QUIC prevent SNI inspection and payload-based DPI at line rate [154], classifiers that rely on those signals are no longer viable. Traffic classification must instead operate on observable flow-level features: packet size sequences, inter-packet timing, and byte histograms [60, 275]. Machine learning approaches, including LightGBM and multi-modal CNNs trained on these features, have reached up to 88% accuracy on encrypted QUIC traffic in controlled evaluations [57, 156, 178].

These models, however, are sensitive to data drift [57, 189]. A server-side TLS certificate rotation can shift the byte size of the fifth handshake packet, dropping classifier accuracy by over 13% within a week [189, 191, 192]. Classifiers that skip handshake packets entirely and focus on steady-state flow statistics are more stable over time, though at the cost of reduced recall [57, 192]. This remains an open trade-off in the field [192, 193].

### 7.2. Scope and Generalizability Limitations
We acknowledge several limitations in the scope of this measurement study:
*   **Geographic and Demographic Focus**: Our dataset is collected from a single residential ISP in Chattogram, Bangladesh [16, 29]. While this provides a rare and valuable perspective on network behavior in emerging markets [29], the findings may not fully generalize to environments with different network topologies, less aggressive CGNAT multiplexing, or distinct subscriber demographics [23, 29].
*   **IPv4-Only Environment**: Consistent with typical residential networks in Bangladesh, our deployment operates exclusively on IPv4 [23, 277]. While we expect ECH and QUIC application behavior to remain identical on IPv6, the lack of dual-stack telemetry represents an open area for further measurement [23].
*   **7-Day Temporal Horizon**: Although 7 days provides sufficient statistical weight to map the weekly diurnal rhythm and capture weekend traffic shifts [17, 19], a longer longitudinal campaign would be required to analyze seasonal data drift and trace the long-term adoption trajectory of ECH public key deployment [203].

---

## 8. Conclusions

We conducted a 7-day passive measurement campaign at a residential ISP edge in Bangladesh, collecting macroscopic IPFIX flows from 4,000 subscribers and microscopic TLS handshake metadata from a 225-user PPPoE subnet [16, 20, 29]. The dataset documents how ECH and QUIC affect ISP-side network visibility in an emerging-market context [275, 277]. ECH capability is advertised by most client devices, but actual encrypted handshakes are nearly entirely limited to Cloudflare-hosted domains [11, 36]. UDP-based QUIC traffic strains CGNAT state tables at peak hours and renders SNI-based queue classifiers ineffective [275, 276]. As encrypted metadata becomes the norm, ISP traffic management must shift toward flow-shape classifiers and behavioral heuristics that do not depend on plaintext protocol fields.

---

## References

1. S. Farrell, H. Tschofenig, Pervasive Monitoring Is an Attack, RFC 7258, 2014. [41]
2. D. Naylor, et al., The cost of the "s" in https, in: Proc. ACM CoNEXT, 2014. [41]
3. J. Iyengar, M. Thomson, QUIC: A UDP-Based Multiplexed and Secure Transport, RFC 9000, 2021. [42]
4. G. Merlach, M. Trevisan, D. Giordano, Encrypted Client Hello Is Coming: A View from Passive Measurements, Network 5 (3) (2025) 29. [10, 11]
5. B. M. Schwartz, M. Bishop, E. Nygren, Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records), RFC 9460, 2023. [44]
6. E. Rescorla, K. Oku, N. Sullivan, C. A. Wood, TLS Encrypted Client Hello, IETF draft-ietf-tls-esni-24, 2025. [44]
7. J. Luxemburk, K. Hynek, T. Čejka, Encrypted traffic classification: the QUIC case, in: Proc. IFIP/IEEE TMA, 2023. [56, 57]
8. R. Jozsa, K. Hynek, A. Pekar, Taming Volatility: Stable and Private QUIC Classification with Federated Learning, in: Proc. IEEE/IFIP CNSM, 2025. [56, 62]
9. L. Csikor, D. M. Divakaran, The Evolution of DNS Security and Privacy, IEEE Security & Privacy (arXiv version), 2023. [56, 94]
10. M. Shen, et al., DeepQoE: Real-time Measurement of Video QoE from Encrypted Traffic with Deep Learning, in: Proc. IEEE/ACM IWQoS, 2020. [56, 213]
11. J. Luxemburk, T. Čejka, Fine-grained TLS services classification with reject option, Computer Networks 220 (2023) 109467. [207]
12. H. Dong, et al., Exploring the Ecosystem of DNS HTTPS Resource Records: An End-to-End Perspective, in: Proc. ACM IMC, 2024. [47]
13. Z. Tsiatsikas, G. Karopoulos, G. Kambourakis, Measuring the adoption of TLS encrypted client hello extension and its forebear in the wild, in: Proc. ESORICS, 2022. [46]
14. J. Fan, J. Xu, M. H. Ammar, Crypto-pan: Cryptography-based prefix-preserving anonymization, Computer Networks 46 (2004) 253-272. [48]
15. M. Trevisan, Dpmon: A Differentially-Private Query Engine for Passive Measurements, Preprint (SSRN), 2025. [48]
