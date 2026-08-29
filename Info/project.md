Excellent choice. This is the path of a serious network engineer and researcher. By abandoning the crowded "machine learning for IDS" space and pivoting to **Empirical Network Measurement**, you are targeting a massive blind spot in current networking literature.

Because we are in 2026, the rollout of HTTP/3 (QUIC) and Encrypted Client Hello (ECH) by major players (Google, Cloudflare, Apple) is aggressively blinding ISPs. Traditional Deep Packet Inspection (DPI) boxes are failing.

Furthermore, I note your location is Bangladesh. **This is a massive strategic advantage for publication.** Top measurement conferences (like ACM IMC, PAM, or journals like _Computer Communication Review_) are desperate for data from the "Global South." 90% of network measurement papers come from US or European university campus networks. A paper detailing the protocol shift in a real South Asian residential ISP will instantly catch a reviewer's eye.

Here is the exact blueprint to execute and write this paper over your 7-day window.

---

### Phase 1: The Technical Architecture (MikroTik to Server)

You cannot send 4,000 users' raw payloads to a 750 GB server. We must split the telemetry into a **Macroscopic** view and a **Microscopic** view.

**1. Macroscopic View (All 4,000 Users): NetFlow/IPFIX**

- **Action:** Configure the MikroTik CCR to export IPFIX (NetFlow v10) for _all_ traffic.
- **Destination:** Your home server running `vflow` or `Logstash`.
- **Configuration:** Set active flow timeout to 60s, inactive to 15s.
- **Purpose:** This proves the sheer volume shift. You will measure total TCP Port 443 bytes vs. UDP Port 443 bytes across the entire ISP.

**2. Microscopic View (Targeted Subset): Zeek via Port Mirroring**

- **Action:** Select a specific `/24` subnet (e.g., 254 active residential PPPoE clients).
- **Mechanism:** Use MikroTik's **TZSP (TaZmen Sniffer Protocol)** or a direct VLAN mirror to send just this subnet's raw packets to your home server.
- **Destination:** Your server running **Zeek**. Zeek will parse the packets in RAM, write the metadata to logs, and discard the heavy payloads.
- **Storage:** Zeek logs for 250 users over 7 days will easily fit within 50–100 GB.

---

### Phase 2: The Data Schema & Feature Engineering

You are not doing machine learning here; you are doing rigorous statistical extraction.

**From Zeek (`ssl.log` and `conn.log`):**

1. **The QUIC Identifier:** Filter `conn.log` for `proto == udp` and `port == 443`. Zeek has a QUIC analyzer; look at the `history` and `service` fields to confirm HTTP/3.
2. **The ECH Identifier:** This is the crux of your paper. How do you know ECH is being used?

- Look at `ssl.log`.
- When ECH is active, the outer SNI (Server Name Indication) is usually a generic dummy name (e.g., `cloudflare-ech.com` or `tls-ech.dev`), while the real SNI is encrypted inside.
- Track the ratio of "Valid specific SNIs" (e.g., `netflix.com`) vs "Dummy ECH SNIs" vs "Blank/Missing SNIs".

3. **TLS Versioning:** Track the strict adoption of TLS 1.3 vs legacy TLS 1.2.

**From NetFlow/IPFIX:**

1. **Flow Duration & Byte Ratios:** Calculate the average flow duration of QUIC vs TCP. (QUIC connection establishment is 0-RTT, meaning it sets up faster and often behaves differently).
2. **Packet Size Distribution:** Calculate the mean and variance of packet sizes for UDP/443 vs TCP/443.

---

### Phase 3: The 7-Day Execution Timeline

- **Day 1 (Setup & Sanity Check):** Configure TZSP and IPFIX. Let it run for 4 hours. Download the logs and verify that Zeek is actually logging `ssl.log` for UDP traffic (QUIC). _Critical:_ Ensure your server's CPU is not maxing out and dropping packets.
- **Day 2 - 3 (Weekday Profiling):** Capture standard daytime traffic (work-from-home, background IoT).
- **Day 4 - 5 (The Entertainment Shift):** Capture the Thursday/Friday night shift to heavy streaming (Netflix/YouTube), which heavily biases toward QUIC.
- **Day 6 (The Weekend Peak):** Capture Saturday.
- **Day 7 (Anonymization & Export):**
- Stop the capture.
- **Crucial Step:** Write a Python script using `hashlib` with a secret salt to convert every IP address in the logs to a pseudo-anonymized string (e.g., `192.168.1.5` -> `Client_A_492`).
- Convert all Zeek TSV logs and NetFlow data to **Apache Parquet** format for fast querying in Pandas/Polars.

---

### Phase 4: The Paper Structure (Designed for Q1 / Top Tier)

Do not write this like a standard dataset paper. Write it as an **observational study**.

**Title:** _Going Dark at the Edge: A 7-Day Empirical Measurement of QUIC and Encrypted Client Hello in a South Asian ISP_

**Abstract:** State the problem (encryption is blinding ISPs), your unique vantage point (real ISP, 4000 users, non-Western demographic), and your hard findings (e.g., "We observe that X% of UDP/443 traffic now utilizes ECH, degrading ISP visibility by Y%").

**Section 1: Introduction**

- The evolution from cleartext HTTP -> HTTPS -> TLS 1.3 -> QUIC -> ECH.
- Why lab setups fail to capture the true residential deployment of these protocols.
- Your core contributions.

**Section 2: Background & Threat to ISP Engineering**

- Explain how ISPs historically used SNI (Server Name) for zero-rating (free Facebook/WhatsApp data), parental controls, and QoS queuing. Explain exactly how ECH breaks this mathematically.

**Section 3: Methodology & Ethical Considerations**

- Detail the MikroTik CCR + Zeek TZSP architecture.
- **Ethics Statement:** Explicitly state that no payloads were captured, no DPI was performed, users were strictly anonymized via hashed IPs, and data was collected strictly for network management research. _Reviewers will reject the paper without this._

**Section 4: Macroscopic Analysis (The NetFlow View)**

- _Figure 1:_ A time-series graph showing the 7-day diurnal rhythm. Two lines: Total TCP/443 Volume vs. Total UDP/443 (QUIC) Volume.
- _Analysis:_ Prove the day-over-day dominance of QUIC during peak streaming hours.

**Section 5: Microscopic Analysis (The ECH View)**

- _Figure 2:_ A pie chart or stacked bar chart of TLS connections from the Zeek logs. Breakdown: TLS 1.2 (Clear SNI), TLS 1.3 (Clear SNI), and TLS 1.3 (ECH Dummy SNI).
- _Analysis:_ Identify which ASNs (e.g., Cloudflare, Google) are forcing ECH the most aggressively onto your clients.

**Section 6: Impact on Traffic Engineering**

- Compare the statistical properties (packet sizes, flow durations) of ECH/QUIC flows vs legacy HTTPS.
- _Insight:_ Prove that because QUIC encrypts transport-layer flags (which NetFlow cannot see), the MikroTik's traditional active queue management (AQM) is operating blind.

**Section 7: Conclusion**

- Summarize how the "blind ISP" era is fully here, and call for new QoS paradigms that do not rely on SNI.

---

### What makes this "Acceptable" to Reviewers?

1. **Zero "AI hype":** Reviewers are exhausted by "I used Random Forest to get 99% accuracy." A paper presenting clean, hard statistical measurements of a real network is a breath of fresh air.
2. **The Geographic Novelty:** Explicitly mention the geographic context. Internet usage patterns in emerging markets (mobile-heavy, specific CDN caches) differ from North America. This makes your dataset and findings inherently unique.
3. **Actionable Intelligence:** You aren't just observing; you are pointing out that ISP hardware (like the MikroTik CCR's standard queue trees) needs fundamental software updates to handle ECH/QUIC dominance.

**Your immediate next step:** Log into your MikroTik, set up a TZSP mirror for a small `/24` subnet, point it to your server, and verify that Zeek can parse the UDP/443 traffic without crashing your CPU. Once you confirm the pipeline works, you are ready to start the 7-day clock.
