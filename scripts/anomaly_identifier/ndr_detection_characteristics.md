# PCAP Threat-Hunting Reference

## Network-Observable Characteristics Mapped to MITRE ATT&CK, ATT&CK for ICS, and MITRE ATLAS

---

| Field | Value |
|---|---|
| **Document type** | Analyst reference / hunt playbook |
| **Audience** | Network security analysts, SOC tier 2–3, IR, OT security, detection engineers |
| **Scope** | Characteristics observable in a packet capture (PCAP/PCAPNG) or its derived flow and protocol logs |
| **Frameworks** | MITRE ATT&CK Enterprise v19.2 (Apr 2026) · MITRE ATT&CK for ICS v19.2 · MITRE ATLAS v5.6.0 |
| **Status** | Generic — framework-level, not tied to any single capture |
| **Date** | 2026-08-17 |

---

## 0. How to read this document

This is a **catalogue of observables**, not a signature set. Each entry describes something you can measure in a capture, why an adversary produces it, how to measure it, what benign activity looks the same, and which ATT&CK/ATLAS techniques it evidences.

### Notation used in indicator cards

| Field | Meaning |
|---|---|
| **Observable** | The measurable property |
| **Adversary rationale** | Why an attacker generates this |
| **Measurement** | How to extract it (tool-agnostic logic, plus example tooling) |
| **Threshold / tuning** | Starting values and what drives them |
| **ATT&CK / ATLAS** | Technique IDs with tactic |
| **Benign twins** | Legitimate causes — the false-positive catalogue |
| **Pivot** | What to look at next if the indicator fires |
| **Confidence** | Typical standalone confidence: Low / Medium / High |

### A note on framework versions

ATT&CK v19 (October 2025 → v19.x, current v19.2 April 2026) made two changes that materially affect network-analysis mappings and that older playbooks will have wrong:

- **Defense Evasion (TA0005) was split.** `TA0005` is now **Stealth** (evading detection) and a new tactic **`TA0112` Defense Impairment** covers disabling or weakening controls. Techniques such as *Downgrade Attack* (`T1689`), *Weaken Encryption* (`T1600`), *Network Boundary Bridging* (`T1599`), and *Disable or Modify System Firewall* (`T1686`) now sit under Defense Impairment.
- **ATT&CK for ICS was consolidated.** Several long-standing T0xxx techniques were revoked and folded into new parents: **`T1692` Unauthorized Message** (with `.001` Command Message and `.002` Reporting Message) absorbs the old "Unauthorized Command Message" / "Spoof Reporting Message" concepts; **`T1694` Insecure Credentials** (`.001` Default, `.002` Hardcoded) replaces the separate default/hardcoded credential techniques; **`T1693` Modify Firmware**, **`T1691` Block Operational Technology Message**, and **`T1695` Block Communications** are new. `T0846` Remote System Discovery and `T0843` Program Download gained sub-techniques.
- **`T1562` Impair Defenses was retired** and its former sub-techniques promoted to standalone techniques under Defense Impairment — notably **`T1685` Disable or Modify Tools** (with log-clearing sub-techniques) and **`T1686` Disable or Modify System Firewall**. Any playbook still citing `T1562.x` needs remapping.

ATLAS v5.6.0 completed its **"ML" → "AI" rename** (e.g. *ML Model Inference API Access* → **AI Model Inference API Access**, `AML.T0040`). Mappings written against older ATLAS releases will carry stale names even where IDs are unchanged.

---

## 1. Analysis methodology

Work the capture in this order. Skipping straight to indicator hunting on an un-baselined capture produces noise.

```
  ┌─────────────────────────────────────────────────────────────┐
  │ STAGE 0 — Evidence integrity                                │
  │   Is this capture trustworthy and complete?                 │
  ├─────────────────────────────────────────────────────────────┤
  │ STAGE 1 — Inventory & topology reconstruction               │
  │   What hosts, subnets, protocols, and zones exist?          │
  ├─────────────────────────────────────────────────────────────┤
  │ STAGE 2 — Baseline & peer-group construction                │
  │   What is normal for each host role and each zone edge?     │
  ├─────────────────────────────────────────────────────────────┤
  │ STAGE 3 — Indicator sweep (Sections 3–8 of this document)   │
  │   Packet · Flow · Protocol · IP/Host · Connection levels    │
  ├─────────────────────────────────────────────────────────────┤
  │ STAGE 4 — Corroboration & pivoting                          │
  │   Cluster indicators by host, by peer, by time window       │
  ├─────────────────────────────────────────────────────────────┤
  │ STAGE 5 — Technique mapping & narrative                     │
  │   Assemble into a tactic-ordered kill chain with confidence │
  └─────────────────────────────────────────────────────────────┘
```

### 1.1 Stage 0 — Evidence integrity (do this first, always)

An analyst who reports "no suspicious connections found" without qualifying capture completeness has produced a misleading result. Establish and state these limits:

| Check | Why it matters | How |
|---|---|---|
| **Snaplen truncation** | If frames were captured at 96 or 128 bytes, all payload analysis (Sections 5, 7) is impossible and the absence of findings is meaningless | `capinfos -c -s`; compare `frame.cap_len` vs `frame.len` |
| **Drop counts / capture gaps** | Dropped packets fabricate "short flows" and destroy beacon periodicity | `capinfos`; look for `pcapng` Interface Statistics blocks; histogram inter-packet gaps |
| **Directionality** | A SPAN configured on one direction makes every flow look asymmetric and every exfil ratio look extreme | Check that SYN/SYN-ACK pairs both appear |
| **Duplicate frames** | SPAN/TAP aggregation duplicates packets, inflating volume and creating fake retransmissions | Dedupe on (IP ID, seq, payload hash) |
| **Clock accuracy & skew** | Beacon-period and off-hours analysis depend on trustworthy timestamps | Compare against NTP traffic in the capture; check for backward time jumps |
| **Capture point placement** | A sensor inside a NAT boundary hides true internal sources; one outside hides internal lateral movement entirely | Reconcile observed subnets against the network diagram |
| **Encryption coverage** | If 95% of bytes are TLS 1.3 with ECH, payload-based indicators are unavailable and you must lean on flow/metadata indicators | Ratio of encrypted to inspectable bytes |
| **Time window** | Beaconing with a 24-hour period is invisible in a 30-minute capture; "long-lived flow" is meaningless if the capture is shorter than the flow | State capture duration explicitly |

> **Reporting rule:** every finding-free hunt must be reported as *"no evidence of X within the limits of this capture"*, with the limits enumerated. "No suspicious connections found" is a claim the evidence usually cannot support.

### 1.2 Stage 1 — Inventory

Build, at minimum: host inventory (IP, MAC, OUI/vendor, inferred OS, inferred role), subnet inventory, protocol inventory with byte and flow counts, and a **zone adjacency matrix** — which zone pairs communicate, over which protocols, in which direction. The zone matrix is the single highest-value artefact for hunting, because most serious findings are *edges that should not exist*.

### 1.3 Stage 2 — Baselining

Three baseline types, in increasing order of usefulness:

- **Protocol baseline** — what the RFC/vendor says normal looks like (e.g. DNS responses should follow queries; Modbus writes should come only from a master).
- **Peer-group baseline** — what the other 39 workstations in this subnet do. Deviation from peer group is far more discriminating than deviation from an absolute threshold.
- **Temporal baseline** — what this host did yesterday, last week, at this hour. Requires historical data; if unavailable, state that as a limitation.

### 1.4 Stage 4/5 — Corroboration and scoring

Aggregate indicator hits per host and per host-pair. A practical scoring model:

```
host_score = Σ (indicator_weight × confidence × asset_criticality_multiplier)
```

with kill-chain **breadth** weighted heavily: a host with one high-weight indicator in a single tactic is usually a false positive; a host with medium indicators spanning Discovery → Lateral Movement → Collection → Exfiltration is an incident. Report the tactic *sequence*, not just the technique *set*.
---

## 2. Part A — The eight nominated indicators

These are the eight characteristics named in the analysis request, expanded into full indicator cards. They are the correct starting set; Sections 3–8 extend them.

---

### A-1 · Short-lived flows

| | |
|---|---|
| **Observable** | Flows whose total duration sits in the extreme low tail of the duration distribution — typically sub-second, often a handful of packets, frequently a complete TCP handshake followed immediately by FIN or RST, or a single UDP datagram pair |
| **Adversary rationale** | Minimise sensor dwell time; complete an action (a check-in, a probe, a single command fetch) inside a window shorter than most flow-export timeouts; avoid session-based inspection that only triggers on established, sustained connections |
| **Confidence** | **Low standalone** — this is a very noisy indicator on its own |

**Measurement**

- Build the duration distribution per protocol and per zone edge, not globally. A 40 ms DNS exchange and a 40 ms TLS session mean entirely different things.
- Separate three distinct sub-populations, because they map to different techniques:
  1. **Failed connections** — SYN with no SYN-ACK, or SYN → RST. These are *scanning*, not stealth C2.
  2. **Successful but tiny** — full handshake, <10 packets, immediate graceful close. These are *check-ins*, *health probes*, or *beacons*.
  3. **Established then abruptly reset** — handshake completes, then RST mid-stream. Can indicate protocol mismatch, an IPS reset, or session hijack.
- Correlate short flows with **repetition**: a single short flow is noise; 2,000 short flows from one host to one destination at a fixed interval is a beacon (see A-5).

**Threshold / tuning starting points**

| Population | Starting threshold | Tuning driver |
|---|---|---|
| TCP "tiny successful" | duration < 1 s AND total packets ≤ 12 AND payload bytes < 1 KB | Application keepalive behaviour |
| TCP "failed" | SYN with no SYN-ACK within RTO | Normal service-down noise |
| UDP micro-flow | single request/response pair, < 512 B | DNS/NTP/mDNS dominate here — exclude by port first |

**ATT&CK / ATLAS mapping**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1046` Network Service Discovery | Discovery (TA0007) | Failed short flows fanning out across ports |
| `T1595.001` Scanning IP Blocks / `T1595.002` Vulnerability Scanning | Reconnaissance (TA0043) | Short failed flows from an external source |
| `T1018` Remote System Discovery | Discovery (TA0007) | Short flows fanning out across hosts on one port |
| `T1071` Application Layer Protocol | Command and Control (TA0011) | Short *successful* periodic flows = beacon check-in |
| `T1102.003` One-Way Communication | Command and Control (TA0011) | Very short one-directional fetches from a web service |
| `T1205.001` Port Knocking | Stealth (TA0005) / Persistence / C2 | Short failed flows to a *specific ordered sequence* of ports, followed by a successful connection elsewhere |
| `T0846.001` Port Scan (ICS) | Discovery | Short failed flows against OT device ports (502, 102, 20000, 44818, 47808) |
| `T1030` Data Transfer Size Limits | Exfiltration (TA0010) | Many short flows each carrying an identically-sized chunk |

**Benign twins**

Health checks and load-balancer probes; service-discovery polling; DNS and NTP; TCP keepalive re-establishment after idle timeout; port-scanning by the organisation's own vulnerability scanner; connection-pool churn in microservice architectures; captive-portal and connectivity-check traffic; failed connections caused simply by a decommissioned server.

**Pivot**

→ Are the short flows *periodic*? (A-5) → Is the destination port non-standard? (A-4) → Is the destination newly observed? (§6) → Does a longer flow to the same destination appear later (knock-then-connect)? → Is there an ordered port sequence?

---

### A-2 · Long-lived flows

| | |
|---|---|
| **Observable** | Flows whose duration sits in the extreme high tail — hours to days — often with low average throughput, sparse packets, and long idle gaps punctuated by small keepalives |
| **Adversary rationale** | Maintain an interactive or on-demand channel without repeated connection setup (fewer connection events to alert on); tunnel other protocols inside one long-lived session; sustain a slow exfiltration under a rate threshold |
| **Confidence** | **Medium** — more discriminating than A-1, especially when the protocol does not normally hold sessions open |

**Measurement**

- Rank flows by duration per protocol. Flag flows exceeding the 99th percentile *for that protocol*.
- Compute the **duration-to-volume ratio**. The interesting class is **long duration + low volume** (an idle control channel), which is quite different from **long duration + high volume** (a backup job — see A-3).
- Characterise the **keepalive signature**: interval regularity, packet size uniformity, and whether keepalives are TCP-layer (zero-length, ACK-only) or application-layer (small payloads). Application-layer keepalives on a long-idle session are more suspicious.
- Look for **traffic bursts inside a long session**: an interactive operator session shows idle periods interrupted by bursts with human-scale timing (see §8, C-6 interactivity analysis).

**Threshold / tuning starting points**

| Signal | Starting threshold |
|---|---|
| Duration | > 99th percentile for the protocol, or > 4 h absolute for protocols that normally close in seconds (HTTP, DNS) |
| Low-and-slow | duration > 1 h AND mean throughput < 1 kbit/s AND > 20 packets |
| Idle-gap regularity | coefficient of variation of inter-packet gaps < 0.1 over ≥ 20 gaps |

**ATT&CK / ATLAS mapping**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1071` Application Layer Protocol (`.001` Web, `.004` DNS, `.005` Pub/Sub) | C2 (TA0011) | Persistent channel wearing a normal protocol |
| `T1573.001/.002` Encrypted Channel | C2 (TA0011) | Long-lived TLS or custom-crypto session |
| `T1572` Protocol Tunneling | C2 (TA0011) | Long-lived session carrying an inner protocol |
| `T1090.001/.002/.003` Proxy | C2 (TA0011) | Long-lived relay/pivot session |
| `T1219` Remote Access Tools (`.001` IDE Tunneling, `.002` Remote Desktop Software) | C2 (TA0011) | Legitimate RAT/RMM or IDE tunnel held open |
| `T1021.001/.004/.005/.006` Remote Services | Lateral Movement (TA0008) | Long RDP/SSH/VNC/WinRM sessions, especially off-hours |
| `T1008` Fallback Channels | C2 (TA0011) | A second long-lived channel that activates when the first dies |
| `T1041` Exfiltration Over C2 Channel | Exfiltration (TA0010) | Slow drain inside the persistent session |
| `T1205.002` Socket Filters | Stealth / Persistence / C2 | Passive backdoor holding a socket |
| `AML.T0072` Reverse Shell | C2 (AML.TA0014) | Long-lived outbound shell from an AI/ML or agent host |
| `T0886` Remote Services (ICS) / `T0822` External Remote Services | Lateral Movement / Initial Access | Persistent vendor or engineering session into OT |
| `T0884` Connection Proxy (ICS) | C2 | Long-lived relay into the process network |

**Benign twins**

Database connection pools; message brokers (AMQP, MQTT, Kafka) that hold sessions open by design; VPN and SD-WAN tunnels; RDP/SSH sessions left open by admins; monitoring agents; OPC UA subscriptions and Modbus polling sessions (in OT, long-lived is the *norm*, not the exception); WebSocket applications; software-update and telemetry agents; IMAP IDLE.

**Pivot**

→ Is the peer external and newly observed? → Does the byte ratio skew outbound? (A-3) → Does the JA3/JA4 fingerprint match a known RAT or a client that shouldn't exist on this host? (§5) → Does the session show human-timing bursts? → Is the source host's *role* consistent with holding this session?

> **OT caveat:** in ICS/SCADA segments the long-lived-flow indicator inverts. Supervisory-to-field sessions are *expected* to be long-lived and periodic. There, the anomaly is a **short-lived or newly-appearing** session to a controller, or a long-lived session from an **unexpected source**.

---

### A-3 · Heavy flows

| | |
|---|---|
| **Observable** | Flows in the extreme high tail of byte volume, packet count, or throughput; or aggregate host-level volume far above peer group |
| **Adversary rationale** | Bulk staging and extraction of collected data; or, in the opposite direction, resource exhaustion of a target |
| **Confidence** | **Medium–High** when combined with directional asymmetry and destination novelty |

**Measurement**

Volume alone is weak. The discriminating features are:

1. **Directional asymmetry.** Compute `bytes_out / bytes_in` per flow and per host-pair. Normal client behaviour is heavily *inbound*-skewed (you download more than you upload). An outbound-skewed heavy flow from a workstation is the classic exfiltration shape. Flag `bytes_out/bytes_in > 5` with `bytes_out > 10 MB` as a starting point.
2. **Novelty of the destination.** Heavy to a known backup target is routine; heavy to a first-seen ASN is not.
3. **Role inversion.** A client-role host emitting server-scale volume.
4. **Compression/encryption entropy.** High-entropy payload inside a nominally plaintext protocol suggests an encrypted archive being moved (§3, P-16).
5. **Rate shape.** Exfiltration is often *rate-limited and steady* (deliberately below a threshold); DoS is *bursty and maximal*. Plot throughput over time, don't just sum bytes.
6. **Flow count vs. byte count.** DoS variants split into two shapes: few flows / enormous bytes (volumetric flood) and enormous flows / few bytes each (connection-exhaustion flood). Both are "heavy" but map to different techniques.

**ATT&CK / ATLAS mapping — exfiltration direction**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1041` Exfiltration Over C2 Channel | Exfiltration (TA0010) | Bulk egress inside the existing C2 session |
| `T1048.001/.002/.003` Exfiltration Over Alternative Protocol | Exfiltration | Bulk egress over a protocol distinct from C2 (encrypted or not) |
| `T1567.001/.002/.003/.004` Exfiltration Over Web Service | Exfiltration | Egress to code repos, cloud storage, paste sites, webhooks |
| `T1020` Automated Exfiltration | Exfiltration | Repeated, identically-shaped bulk transfers |
| `T1030` Data Transfer Size Limits | Exfiltration | Volume deliberately chunked into uniform sub-threshold pieces |
| `T1029` Scheduled Transfer | Exfiltration | Bulk transfers confined to a recurring window |
| `T1560` Archive Collected Data | Collection (TA0009) | High-entropy, compressible-but-incompressible payload in transit |
| `T1074` Data Staged | Collection | Heavy *internal* flow to a staging host preceding egress |
| `T1005`/`T1039`/`T1213` Data from Local System / Network Shared Drive / Information Repositories | Collection | Heavy inbound SMB/HTTP reads to the staging host |
| `T0882` Theft of Operational Information (ICS) | Impact | Bulk extraction of process/historian data |
| `T0845` Program Upload (ICS) | Collection | Bulk read of controller logic |
| `AML.T0025` Exfiltration via Cyber Means | Exfiltration (AML.TA0010) | Bulk egress of model/dataset artefacts |
| `AML.T0035` AI Artifact Collection | Collection (AML.TA0009) | Heavy internal pulls of model weights, checkpoints, datasets |
| `AML.T0048.004` AI Intellectual Property Theft | Impact (AML.TA0011) | Outcome of the above |

**ATT&CK / ATLAS mapping — denial direction**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1498.001` Direct Network Flood | Impact (TA0040) | Volumetric flood, many sources or spoofed sources |
| `T1498.002` Reflection Amplification | Impact | Small requests out, huge responses in, from reflectors (DNS, NTP, SSDP, memcached, CLDAP) |
| `T1499.001` OS Exhaustion Flood | Impact | SYN flood; half-open state accumulation |
| `T1499.002` Service Exhaustion Flood | Impact | Connection exhaustion against one service |
| `T1499.003` Application Exhaustion Flood | Impact | Expensive-request flood (search, report generation, inference) |
| `T1499.004` Application or System Exploitation | Impact | Malformed input causing crash — low volume, high effect |
| `T0814` Denial of Service (ICS) | Inhibit Response Function | Flooding a controller or protocol stack |
| `T0816` Device Restart/Shutdown (ICS) | Inhibit Response Function | Result of resource exhaustion or a restart command |
| `AML.T0029` Denial of AI Service | Impact (AML.TA0011) | Flooding an inference endpoint |
| `AML.T0034` Cost Harvesting | Impact | Sustained expensive inference to inflate cost |
| `AML.T0046` Spamming AI System with Chaff Data | Impact | High-volume junk submissions |

**Benign twins**

Backups, replication, VM/image distribution, patch and OS update pushes, CI artefact transfers, video conferencing and streaming, log shipping to a SIEM, data-warehouse ETL, cloud sync clients (OneDrive, Dropbox, Drive), historian replication in OT, and legitimate large uploads by users.

**Pivot**

→ What is the destination's ASN, registration age, and reputation? → Was there a DNS lookup first, or a bare-IP connection? (§6) → Does the source host show prior Collection-stage indicators (mass SMB reads, `T1039`)? → Is the transfer size suspiciously uniform across repeats? → Does the timing align with a schedule?

---

### A-4 · Non-standard ports

| | |
|---|---|
| **Observable** | (a) A known protocol running on a port not assigned to it; (b) an unknown/unclassifiable protocol on any port; (c) a well-known port carrying a protocol other than its assigned one |
| **Adversary rationale** | Evade port-based ACLs and inspection policy; hide a C2 protocol behind a port that is allowed outbound; or, conversely, run a non-standard protocol on 443/80 precisely *because* those are allowed |
| **Confidence** | **Medium** — high when paired with protocol/port mismatch rather than just an unusual port number |

**Measurement**

Three separate tests; run all three, they catch different things:

1. **Port-not-in-policy.** Compare observed destination ports against the allow-list implied by the zone matrix. Simple, and catches lazy attackers.
2. **Protocol-on-wrong-port** (the strong test). Use protocol dissection independent of port — heuristic dissectors, DPI, or byte-pattern classification — and flag every case where `detected_protocol ≠ port_assignment`. Examples: TLS on 8443 is unremarkable; **SSH on 443**, **HTTP on 53**, **TLS on 4444**, **DNS on 8080**, or **an unknown binary protocol on 443** are all worth chasing.
3. **Wrong-protocol-on-right-port** (the strongest test). Traffic on 443 that does not begin with a TLS `ClientHello`; traffic on 53 that is not DNS-formatted; traffic on 80 with no HTTP request line. This is how tunnels and custom C2 hide.

Additionally: track **ephemeral-port-as-destination** (a listener on a high random port), and **service ports that appear for the first time in the capture**.

**High-value port classes to enumerate explicitly**

| Class | Examples | Note |
|---|---|---|
| Common C2/tooling defaults | 4444, 4443, 8080, 8443, 1337, 31337, 5555, 6666, 9001, 50050 (Cobalt Strike team server) | Default ports are still common in the wild |
| Remote access | 3389, 22, 5900, 5985/5986, 5938 (TeamViewer), 6568/6567 (AnyDesk), 7070 | Compare against approved-tool list |
| Tunneling brokers | 443 to ngrok/localtunnel/Cloudflare Tunnel endpoints, 7000, 4040 | Egress tunnels bypass ingress firewalls entirely |
| Databases exposed | 1433, 3306, 5432, 6379, 9200, 27017, 11211 | Should almost never cross a zone edge |
| OT / ICS | 502 (Modbus), 102 (S7comm/COTP), 20000 (DNP3), 44818 & 2222 (EtherNet/IP-CIP), 47808 (BACnet), 4840 (OPC UA), 2404 (IEC-104), 789 (Red Lion), 1911/4911 (Niagara Fox) | Any of these outside the OT zone is high-signal |
| AI/ML services | 8000/8080 (FastAPI, vLLM), 11434 (Ollama), 5000 (MLflow), 6333 (Qdrant), 19530 (Milvus), 8265 (Ray dashboard), 6006 (TensorBoard) | Exposure of these is an ATLAS-relevant finding |

**ATT&CK / ATLAS mapping**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1571` Non-Standard Port | C2 (TA0011) | The direct mapping |
| `T1572` Protocol Tunneling | C2 | Protocol-on-wrong-port is usually a tunnel |
| `T1001.003` Protocol or Service Impersonation | C2 | Custom protocol dressed as HTTP/TLS on the standard port |
| `T1095` Non-Application Layer Protocol | C2 | Raw TCP/UDP/ICMP with no application layer |
| `T1090.001/.002` Proxy | C2 | Listener on an ephemeral port acting as a relay |
| `T1219` Remote Access Tools | C2 | RMM tools on their vendor ports |
| `T1205.001` Port Knocking | Stealth / Persistence / C2 | Sequence of closed ports preceding a listener opening |
| `T1021.004` SSH / `T1021.001` RDP | Lateral Movement | Remote services relocated to non-default ports |
| `T0885` Commonly Used Port (ICS) | C2 | Adversary deliberately using an allowed OT port for C2 |
| `T0869` Standard Application Layer Protocol (ICS) | C2 | ICS protocol used as the C2 carrier |
| `AML.T0040` AI Model Inference API Access | AI Model Access (AML.TA0000) | Inference endpoint reachable on an unexpected port/zone |

**Benign twins**

Application servers on 8080/8443/9000; developer and test services; Kubernetes NodePorts (30000–32767); passive-FTP data channels; RTP/RTCP media on dynamic UDP ranges; peer-to-peer conferencing; database clients; legacy in-house applications; vendor software with non-IANA defaults.

**Pivot**

→ Dissect the payload to identify the true protocol → check whether the *same* client also talks the same protocol on its standard port (a strong tell) → resolve the destination and check registration age → check the process/service inventory on the host if endpoint telemetry is available.

---

### A-5 · Periodic messages / beaconing

| | |
|---|---|
| **Observable** | Repeated connections or messages from one source to one destination separated by intervals with abnormally low variance, and/or with abnormally uniform payload sizes |
| **Adversary rationale** | Implants poll for tasking on a timer. Even jittered implants retain statistical regularity over enough samples |
| **Confidence** | **High** — periodicity is one of the strongest single network indicators, provided the analysis is done properly |

**Measurement — the four-signal method**

Beacon detection fails when it relies on interval regularity alone. Use all four signals and score:

1. **Interval regularity.** Collect inter-arrival deltas Δt for a (src, dst, dport) tuple. Compute median absolute deviation (MAD) and coefficient of variation (CV = σ/μ). Low CV ⇒ regular. Robust statistics matter — a handful of missed check-ins wrecks a naive standard deviation.
2. **Spectral / autocorrelation analysis.** For jittered beacons, a fixed interval is absent but a dominant frequency persists. Run an FFT or autocorrelation over the packet-time series and look for a sharp peak. This catches ±30–50% jitter that CV-based methods miss.
3. **Payload-size uniformity.** Beacon check-ins carry near-identical byte counts. Compute the CV of request sizes and of response sizes independently. Uniform request size with *variable* response size is the classic "poll for tasking" shape — and a sudden large response is the task being delivered.
4. **Persistence and duty cycle.** How many hours of the capture does the pattern span? Does it survive the user's logoff, or the workstation's idle period? A beacon that continues at 03:00 when the user is absent is far more significant than one that stops.

Also test for **jitter distribution shape**: many frameworks apply uniform random jitter around a base sleep, which produces a distinctive flat-topped histogram rather than a Gaussian one.

**Threshold / tuning starting points**

| Signal | Suspicious | Strong |
|---|---|---|
| Interval CV | < 0.30 | < 0.10 |
| Request-size CV | < 0.20 | < 0.05 |
| Sample count | ≥ 20 intervals | ≥ 100 intervals |
| Duty cycle | > 50% of capture | ~100%, including off-hours |

**ATT&CK / ATLAS mapping**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1071.001/.002/.003/.004/.005` Application Layer Protocol | C2 (TA0011) | The carrier of the beacon |
| `T1573.001/.002` Encrypted Channel | C2 | Encrypted beacon |
| `T1568.001` Fast Flux DNS / `T1568.002` Domain Generation Algorithms / `T1568.003` DNS Calculation | C2 | Periodic resolution attempts, often with high NXDOMAIN |
| `T1102.001` Dead Drop Resolver / `T1102.002` Bidirectional Communication | C2 | Periodic polls of a legitimate web service |
| `T1008` Fallback Channels | C2 | A second periodic pattern that starts when the first stops |
| `T1104` Multi-Stage Channels | C2 | Beacon interval or destination changes after an initial stage |
| `T1029` Scheduled Transfer | Exfiltration (TA0010) | Periodic *bulk* transfers rather than periodic small polls |
| `T1020` Automated Exfiltration | Exfiltration | Automated, therefore regular |
| `T1053` Scheduled Task/Job | Execution / Persistence | Host-side cause of a network periodicity |
| `T0869` Standard Application Layer Protocol (ICS) | C2 | Beacon hidden inside expected ICS polling cadence |
| `AML.T0072` Reverse Shell | C2 (AML.TA0014) | Periodic reconnect attempts of a dropped shell |

**Benign twins — this is where beacon hunting lives or dies**

Almost everything in an enterprise beacons. Software update checkers; AV/EDR agent check-ins; telemetry and crash reporting; monitoring agents (Nagios, Zabbix, Datadog, Prometheus scrape intervals); NTP; DHCP renewals; certificate revocation checks (OCSP/CRL); Windows Group Policy refresh; Kerberos ticket renewal; mail client polling; RSS/calendar sync; keepalives; **and in OT, essentially all supervisory polling of PLCs is by design a perfect beacon.**

The workable approach is **allow-list by destination and by fingerprint**, not by shape. Enumerate the legitimate beacon destinations for your estate once, then hunt everything else. A beacon to an unknown destination is high-signal; a beacon to a vendor's update service is not.

**Pivot**

→ Is the destination on the legitimate-beacon allow-list? → What is the JA3/JA4 of the client and does it match a browser or an unexpected runtime? → Does the beacon interval change after a large response (tasking)? → Do *multiple hosts* beacon to the same destination with the same interval and fingerprint (a campaign)? → Does the beacon survive off-hours?

---

### A-6 · Malicious content in plaintext payloads

| | |
|---|---|
| **Observable** | Attack strings, tooling artefacts, credentials, encoded blobs, shellcode, or executable content visible in unencrypted payloads |
| **Adversary rationale** | Not all traffic is encrypted — internal lateral movement, legacy protocols, OT protocols, and misconfigured services frequently carry attacks in the clear |
| **Confidence** | **High** when a genuine attack pattern is confirmed in context |

**What to search for**

| Category | Indicators |
|---|---|
| **Exploitation strings** | SQLi (`' OR 1=1`, `UNION SELECT`, time-based `SLEEP(`), XSS (`<script`, `javascript:`, `onerror=`), command injection (`;id`, `\|\|whoami`, `$(`, backticks), path traversal (`../`, `..%2f`, `%252e%252e`), template injection (`${jndi:ldap://` — Log4Shell, `{{7*7}}`), deserialization markers (`rO0AB` Java, `AAEAAAD` .NET, `\x80\x04\x95` Python pickle protocol 4) |
| **Shellcode / payload artefacts** | NOP sleds (`\x90\x90...`), egg hunters, `MZ`/`This program cannot be run in DOS mode`, ELF magic `\x7fELF`, PE section names, reflective loader stubs |
| **Encoded blobs** | Long base64 runs in headers, cookies, URIs, or DNS labels; hex-encoded blobs; gzip/deflate inside a field that should be text; XOR-encoded content with a detectable single-byte key |
| **Credentials in the clear** | FTP `USER`/`PASS`, Telnet login sequences, HTTP `Authorization: Basic`, LDAP simple bind, POP3/IMAP `LOGIN`, SNMP community strings, SMTP `AUTH PLAIN`, HTTP form posts to non-TLS endpoints, API keys and bearer tokens in query strings |
| **Tooling fingerprints** | Distinctive user-agents (`sqlmap`, `nikto`, `Nmap Scripting Engine`, `python-requests` on a user workstation), Metasploit default URIs, Cobalt Strike default profile artefacts, webshell parameter names (`cmd=`, `c99`, `eval(`), PowerShell `-enc`/`-EncodedCommand` strings |
| **Data-loss content** | PII/PCI/PHI patterns, source-code fragments, private key headers (`-----BEGIN ... PRIVATE KEY-----`), `.env` contents, connection strings |
| **AI-specific payload content** | Prompt-injection phrasing ("ignore previous instructions", "you are now", "developer mode"), jailbreak scaffolds, system-prompt extraction attempts, injected instructions inside documents/HTML that a RAG pipeline will ingest, zero-width/homoglyph/unicode-tag obfuscation, base64-wrapped prompts |

**Method notes**

- Reassemble streams before searching; attacks split across TCP segments defeat per-packet matching (which is itself an evasion technique).
- Normalise before matching: URL-decode (repeatedly), HTML-decode, base64-decode, and decompress. Multi-layer encoding is standard evasion.
- Compute **per-field entropy**: high entropy in a field that should be human-readable indicates encoding, encryption, or compression.
- Extract and hash transferred files; check against known-bad sets.

**ATT&CK / ATLAS mapping**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1190` Exploit Public-Facing Application | Initial Access (TA0001) | Exploit strings toward an internet-facing service |
| `T1210` Exploitation of Remote Services | Lateral Movement (TA0008) | Exploit strings toward an internal service |
| `T1203` Exploitation for Client Execution | Execution (TA0002) | Malicious document/script content in transit |
| `T1059` Command and Scripting Interpreter | Execution | Commands visible in C2 payload or webshell requests |
| `T1105` Ingress Tool Transfer | C2 (TA0011) | Executable content downloaded |
| `T1570` Lateral Tool Transfer | Lateral Movement | Executable content moved host-to-host |
| `T1132.001/.002` Data Encoding | C2 | Base64/hex/custom encoding of C2 traffic |
| `T1001.001/.002/.003` Data Obfuscation | C2 | Junk data, steganography, protocol impersonation |
| `T1027` Obfuscated Files or Information | Stealth (TA0005) | Packed/encoded payload in transit |
| `T1040` Network Sniffing | Credential Access (TA0006) / Discovery | Credentials being harvestable in the clear is the precondition |
| `T1552.001` Credentials In Files | Credential Access | Secrets moving in the clear |
| `T1659` Content Injection | Initial Access / C2 | Malicious content injected into a legitimate stream |
| `T1071.001` Web Protocols | C2 | HTTP-carried C2 |
| `T1692.001` Unauthorized Message → Command Message (ICS) | Evasion / Impair Process Control | Unauthorised ICS command in a plaintext OT protocol |
| `T1692.002` Unauthorized Message → Reporting Message (ICS) | Evasion | Falsified telemetry sent to the HMI |
| `T0836` Modify Parameter (ICS) | Impair Process Control | Setpoint/register write visible in Modbus/DNP3/S7 payload |
| `AML.T0051.000` LLM Prompt Injection → Direct | Execution (AML.TA0005) | Injection in a request payload to an LLM service |
| `AML.T0051.001` LLM Prompt Injection → Indirect | Execution | Injection embedded in content the model retrieves |
| `AML.T0054` LLM Jailbreak | Privilege Escalation / Defense Evasion | Jailbreak scaffold in payload |
| `AML.T0068` LLM Prompt Obfuscation | Defense Evasion (AML.TA0007) | Encoded/obfuscated prompt on the wire |
| `AML.T0056` Extract LLM System Prompt | Exfiltration (AML.TA0010) | System-prompt extraction attempt |
| `AML.T0057` LLM Data Leakage | Exfiltration | Sensitive data visible in model responses |
| `AML.T0070` RAG Poisoning | — | Malicious instructions written into a retrieval corpus |

**Benign twins**

Security-tool traffic (your own scanner's payloads look exactly like attacks); WAF/IDS test traffic; developers pasting code and payloads; documentation and blog content containing exploit examples; legitimate base64 in APIs, JWTs, SAML assertions, and email; encoded telemetry; security-research browsing.

**Pivot**

→ Did the target respond with success or error? (a 200 with a large body after an injection attempt is very different from a 403) → Was a file transferred immediately afterwards? → Did the source subsequently connect outbound to a new destination? → For OT, was the command accepted and did the process value change?

---

### A-7 · Malicious logins / authentication abuse

| | |
|---|---|
| **Observable** | Authentication exchanges whose pattern, timing, source, or protocol characteristics deviate from normal — visible in Kerberos, NTLM, LDAP, SMB, RDP, SSH, HTTP auth, and OT protocol handshakes |
| **Adversary rationale** | Credential access and reuse is the most common path to lateral movement; the network sees the authentication even when the endpoint does not log it |
| **Confidence** | **High** for specific protocol signatures (Kerberoasting, AS-REP roasting, NTLM relay); Medium for volumetric patterns |

**Measurement by pattern**

| Pattern | Shape on the wire | Mapping |
|---|---|---|
| **Password guessing** | Many auth failures, one account, one target | `T1110.001` |
| **Password spraying** | Few failures each, *many accounts*, one or few targets, often paced to defeat lockout | `T1110.003` |
| **Credential stuffing** | Many account/password pairs, high failure rate, often external source | `T1110.004` |
| **Brute force (generic)** | High auth-attempt rate, low success ratio | `T1110` |
| **Valid-account abuse** | *Successful* auth, but anomalous source/time/target/volume — no failures at all | `T1078` |
| **Kerberoasting** | `TGS-REQ` for service accounts with encryption type **RC4-HMAC (etype 23)** when the domain otherwise uses AES; bursts of TGS requests for many SPNs | `T1558.003` |
| **AS-REP roasting** | `AS-REQ` without pre-authentication (`PA-ENC-TIMESTAMP` absent) returning an AS-REP for accounts with pre-auth disabled | `T1558.004` |
| **Golden / Silver ticket** | Tickets with anomalous lifetimes, missing PAC validation, TGS use without a preceding AS exchange | `T1558.001` / `T1558.002` |
| **Pass-the-hash** | NTLM authentication from a host that normally uses Kerberos; NTLM to many targets in sequence | `T1550.002` |
| **Pass-the-ticket** | Kerberos TGS use from a source that never performed an AS-REQ | `T1550.003` |
| **NTLM relay** | An authentication challenge/response chain where the challenge appears in two sessions; SMB/HTTP/LDAP auth arriving from an unexpected relay host | `T1557.001` |
| **Forced authentication** | Requests that coerce a host to authenticate outbound — SMB UNC paths in documents/URIs, EFSRPC (`PetitPotam`), DFS/PrinterBug RPC calls | `T1187` |
| **Name-resolution poisoning** | Rogue responses to LLMNR/NBT-NS/mDNS queries, followed by an inbound auth attempt to the responder | `T1557.001` |
| **NTLM downgrade** | Negotiation settling on NTLMv1 or session security flags stripped | `T1689`, `T1600` |
| **Anonymous / null session** | SMB session setup with empty user; LDAP anonymous bind; SNMP default community | `T1078.001` Default Accounts, `T1135`, `T1087.002` |
| **Impossible travel / concurrency** | Same account authenticating from geographically or topologically incompatible sources within a short window | `T1078` |
| **Off-hours privileged auth** | Admin account authenticating outside its behavioural window | `T1078.002/.003` |
| **DCSync** | DCERPC `DRSUAPI` `DRSGetNCChanges` from a host that is not a domain controller | `T1003.006` |
| **OT device auth** | OPC UA sessions with `SecurityPolicy=None` or anonymous identity token; default/hardcoded credentials on controllers and HMIs | `T1694.001`, `T1694.002`, `T0859` |

**ATT&CK / ATLAS summary mapping**

`T1110` (+ `.001`, `.003`, `.004`) Brute Force — Credential Access · `T1078` (+ `.001`–`.004`) Valid Accounts — Initial Access / Persistence / Priv Esc / Stealth · `T1558` (+ `.001`–`.005`) Steal or Forge Kerberos Tickets — Credential Access · `T1550` (+ `.002`, `.003`) Use Alternate Authentication Material — Lateral Movement / Defense Impairment · `T1557` (+ `.001`–`.004`) Adversary-in-the-Middle — Credential Access / Collection · `T1187` Forced Authentication — Credential Access · `T1003.006` OS Credential Dumping: DCSync — Credential Access · `T1021` (+ subs) Remote Services — Lateral Movement · `T1556` Modify Authentication Process — Defense Impairment (TA0112) · `T1040` Network Sniffing — Credential Access · **ICS:** `T0859` Valid Accounts, `T1694` Insecure Credentials (`.001` Default, `.002` Hardcoded), `T0886` Remote Services, `T0822` External Remote Services, `T0892` Change Credential · **ATLAS:** `AML.T0012` Valid Accounts (Initial Access / Priv Esc), `AML.T0055` Unsecured Credentials (Credential Access)

**Benign twins**

Users with expired or mistyped passwords; stale cached credentials on phones and services after a password change; service accounts with hardcoded old passwords retrying in a loop; scheduled tasks and scripts authenticating at odd hours; vulnerability scanners performing authenticated scans; legitimate admin activity during a maintenance window; account lockout storms caused by a single misconfigured device.

**Pivot**

→ Did any attempt *succeed*? → What did the account do in the 15 minutes after success? → Does the source host normally authenticate to this target? → Is the encryption type/protocol version consistent with the domain's policy? → Does the same source authenticate to an unusually broad set of targets (spray or ticket reuse)?

---

### A-8 · Malicious file transfers

| | |
|---|---|
| **Observable** | Files moving over the network whose type, name, entropy, direction, or transfer path is anomalous |
| **Adversary rationale** | Tooling must reach the target; collected data must leave; payloads must move laterally |
| **Confidence** | **High** when the artefact type and direction are both anomalous |

**Measurement**

- **Carve files** from reassembled streams across every protocol that can carry them: HTTP(S) where decryptable, SMB2, FTP/FTPS, TFTP, SFTP/SCP, SMTP/IMAP/POP3, NFS, WebDAV, and ICS file-transfer functions. Hash each and record `(src, dst, protocol, direction, filename, size, MIME, hash)`.
- **Classify by magic bytes, not by extension.** `invoice.pdf` beginning with `MZ` is the finding.
- **Score by type-risk × direction × path:**

| Type | Inbound to a workstation | Outbound from a workstation | Internal host-to-host |
|---|---|---|---|
| PE/ELF/Mach-O executable, DLL, driver | Suspicious — `T1105` | Very suspicious | Very suspicious — `T1570` |
| Script (`.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, `.py`) | Suspicious | Suspicious | Suspicious |
| LOLBin / dual-use tools (PsExec, procdump, mimikatz, rclone, WinSCP, plink, ngrok, AnyDesk installer) | High | High | High |
| Encrypted/compressed archive (RAR/7z/ZIP with high entropy) | Low | **High — exfil staging** (`T1560`) | Medium |
| Disk image / VHD / ISO | Medium — container evasion | Medium | Medium |
| Office doc with macro / OLE / RTF | Medium | Low | Medium |
| ML model artefacts (`.pt`, `.pkl`, `.ckpt`, `.safetensors`, `.gguf`, `.onnx`, `.h5`, `.joblib`) | **High if from an unvetted source** — `AML.T0010.003`, `AML.T0011.000` (pickle = arbitrary code execution) | **High — model theft**, `AML.T0025` | High |
| Dataset archives / parquet / TFRecord | Medium — `AML.T0010.002` | High — `AML.T0035` | Medium |
| PLC project files, logic/ladder blocks, firmware images | High — `T0873`, `T1693` | High — `T0845` | High |
| Certificates and private keys | Medium | **High** | High |
| Database dumps (`.sql`, `.bak`, `.dmp`) | Low | **Very high** | High |

- **Transfer-path anomalies:** a workstation serving files to another workstation; a server pulling an executable from the internet; SMB writes to `ADMIN$`, `C$`, or `IPC$` followed by a service creation over `svcctl` (the PsExec pattern); TFTP into an OT segment (firmware/config push); FTP where SFTP is policy.
- **Encrypted-archive detection without decryption:** high, uniform payload entropy plus a filename or size signature, plus poor compressibility.
- **Volume-of-files anomalies:** mass SMB reads across many shares (Collection), or mass writes with changed extensions and high entropy (ransomware encryption in progress — `T1486`).

**ATT&CK / ATLAS mapping**

| Technique | Tactic | Relevance |
|---|---|---|
| `T1105` Ingress Tool Transfer | C2 (TA0011) | Tooling pulled into the environment |
| `T1570` Lateral Tool Transfer | Lateral Movement (TA0008) | Tooling moved host-to-host |
| `T1071.002` File Transfer Protocols | C2 | FTP/TFTP/SMB as the C2 carrier |
| `T1021.002` SMB/Windows Admin Shares | Lateral Movement | Write to admin share |
| `T1560` Archive Collected Data | Collection (TA0009) | Encrypted archive in transit |
| `T1074.001/.002` Data Staged | Collection | Files converging on a staging host |
| `T1048` / `T1567` Exfiltration Over Alternative Protocol / Web Service | Exfiltration (TA0010) | Files leaving |
| `T1486` Data Encrypted for Impact | Impact (TA0040) | Mass high-entropy rewrite over SMB |
| `T1485` Data Destruction / `T1490` Inhibit System Recovery | Impact | Mass deletes; backup/share destruction |
| `T1608` Stage Capabilities | Resource Development (TA0042) | Payload hosted on infrastructure the victim fetches from |
| `T1546`/`T1547` persistence artefacts written over SMB | Persistence (TA0003) | Startup-folder / service-binary writes |
| `T0843` Program Download (`.001` Download All, `.002` Online Edit, `.003` Program Append) — ICS | Lateral Movement | Control logic pushed to a PLC |
| `T0845` Program Upload — ICS | Collection | Control logic read out of a PLC |
| `T1693` Modify Firmware — ICS | Persistence / Inhibit Response / Impair Process Control | Firmware image transferred to a device |
| `T0873` Project File Infection — ICS | Persistence | Engineering project file tampered with |
| `T0867` Lateral Tool Transfer — ICS | Lateral Movement | Tooling moved within OT |
| `AML.T0010.001/.002/.003` AI Supply Chain Compromise (AI Software / Data / Model) | Initial Access (AML.TA0004) | Poisoned model, dataset, or dependency in transit |
| `AML.T0011.000` User Execution → Unsafe AI Artifacts | Execution (AML.TA0005) | Pickle-format model that executes on load |
| `AML.T0035` AI Artifact Collection | Collection (AML.TA0009) | Model/checkpoint/dataset gathering |
| `AML.T0025` Exfiltration via Cyber Means | Exfiltration (AML.TA0010) | Artefacts leaving |
| `AML.T0058` Publish Poisoned Models / `AML.T0019` Publish Poisoned Datasets | Resource Development (AML.TA0003) | Source side of a poisoned artefact fetch |

**Benign twins**

Software deployment and patching; container and package pulls (npm, PyPI, Maven, registries); backups; user file sharing; CI/CD artefacts; legitimate model downloads from an approved registry; vendor firmware updates during a scheduled OT maintenance window; developer tooling.

**Pivot**

→ Hash reputation → who initiated the transfer, and was there a preceding exploit or authentication? → what executed afterwards (endpoint telemetry) → did the receiving host immediately begin new outbound connections? → for OT, was the transfer inside an approved change window with a change ticket?
---

## 3. Part B1 — Packet-level characteristics

Properties of individual frames and headers, independent of flow assembly. These are where evasion, spoofing, and covert channels show up.

| # | Characteristic | What it looks like | Attack / meaning | ATT&CK / ATLAS |
|---|---|---|---|---|
| P-1 | **TTL / hop-limit anomalies** | Packets in one flow with inconsistent TTLs; TTL inconsistent with the claimed OS or with the topological distance; a "LAN" host arriving with TTL 47 | Packet injection into an existing stream; spoofed source; traffic traversing an unexpected path or tunnel; a device NATing/relaying that shouldn't | `T1659` Content Injection (Initial Access / C2); `T1557.002` ARP Cache Poisoning; `T1036` Masquerading (Stealth); `T1090.001` Internal Proxy |
| P-2 | **IP ID field behaviour** | Zero, constant, or globally-incrementing IP IDs; predictable sequences | OS fingerprinting target; idle/zombie scanning; covert channel in the ID field | `T1595.001` Scanning IP Blocks; `T1046`; `T1001` Data Obfuscation |
| P-3 | **TCP flag combinations** | NULL (no flags), FIN-only, XMAS (FIN+PSH+URG), SYN+FIN, SYN+RST, ACK-only to a closed port, URG set with no urgent data | Stealth port scanning; firewall/ACL mapping; IDS evasion; OS fingerprinting | `T1046` Network Service Discovery; `T1595.001/.002`; `T0846.001` Port Scan (ICS) |
| P-4 | **TCP options fingerprint (p0f/OS fingerprint)** | MSS, window scale, SACK-permitted, timestamps, and their *ordering* — inconsistent with the OS the host claims via user-agent or DHCP fingerprint | Host spoofing; a VM/container/tunnel behind a claimed identity; a scanner crafting raw packets | `T1036` Masquerading (Stealth TA0005); `T1595` |
| P-5 | **Initial sequence number (ISN) predictability** | Low-entropy or incrementing ISNs; duplicate ISNs across flows | Blind spoofing / session prediction; crafted packets from a raw socket | `T1499.004` Application or System Exploitation; `T1557` |
| P-6 | **Fragmentation anomalies** | Overlapping fragments, tiny fragments, fragments with conflicting content, fragment floods, MF flag set with no follow-on | Deliberate IDS/IPS evasion via reassembly ambiguity; resource-exhaustion DoS (teardrop-class) | Stealth (TA0005) generally; `T1499.004`; `T1027` Obfuscated Files or Information |
| P-7 | **Malformed / RFC-violating packets** | Bad header lengths, illegal option values, truncated protocol headers, impossible field combinations | Fuzzing; exploitation attempts against protocol stacks; evasion. In OT, malformed frames frequently crash controllers outright | `T1499.004`; `T0814` Denial of Service (ICS); `T0816` Device Restart/Shutdown (ICS) |
| P-8 | **Header-field covert channels** | Entropy or patterned data in IP ID, TCP sequence/ACK numbers, TCP timestamps, TCP urgent pointer, DSCP/ToS, IPv6 flow label, or Ethernet trailer padding | Low-bandwidth covert exfiltration or signalling that no payload inspection will find | `T1001.002` Steganography; `T1095` Non-Application Layer Protocol; `T1048.003` |
| P-9 | **Ethernet padding content** | Non-zero bytes in frames padded to the 60-byte minimum | Data leakage (Etherleak) or deliberate covert channel | `T1001.002` Steganography; `T1040` |
| P-10 | **Timing / inter-arrival covert channels** | Information encoded in the *gaps* between packets rather than their contents; bimodal inter-arrival distributions | Timing covert channel; extremely low bandwidth, extremely hard to detect | `T1001` Data Obfuscation; `T1048.003` |
| P-11 | **TCP window anomalies** | Persistent zero-window; tiny advertised windows held open; window probes never satisfied | Slow-read / connection-holding DoS (Sockstress, slow HTTP class) | `T1499.001` OS Exhaustion Flood; `T1499.002` Service Exhaustion Flood |
| P-12 | **Retransmission / duplicate-ACK rates** | Retransmission ratio far above baseline for a path | Congestion, link fault, or a target under load — corroborates DoS; also a symptom of an in-path device dropping traffic | `T1498`, `T1499` |
| P-13 | **RST injection** | RSTs with TTL, IP ID, or window values inconsistent with the flow's other packets; RST arriving impossibly fast | In-path censorship/blocking device, or an adversary tearing down sessions to force fallback | `T1659` Content Injection; `T1499` |
| P-14 | **Duplicate sequence numbers with differing payloads** | Two packets, same sequence number, different data | Response injection / race against the legitimate server (in-path or on-path attacker) | `T1557` Adversary-in-the-Middle; `T1659` Content Injection |
| P-15 | **ARP anomalies** | Gratuitous ARP storms; one MAC claiming many IPs; an IP whose MAC changes repeatedly; ARP replies without requests | ARP cache poisoning to establish an on-path position — the classic precursor to credential capture and traffic manipulation | `T1557.002` ARP Cache Poisoning (Credential Access / Collection); `T0830` Adversary-in-the-Middle (ICS) |
| P-16 | **Payload entropy per packet** | Shannon entropy ≈ 7.9+ bits/byte inside a protocol field that should be text | Encrypted or compressed content hidden in a plaintext protocol — tunneling, encrypted C2, or an archive being exfiltrated | `T1573` Encrypted Channel; `T1132` Data Encoding; `T1572` Protocol Tunneling; `T1560` Archive Collected Data |
| P-17 | **ICMP payload characteristics** | Echo requests with large or non-standard payloads; echo replies without requests; unusual type/code pairs; ICMP carrying structured data | ICMP tunneling for C2 or exfiltration; also ICMP-based host discovery | `T1095` Non-Application Layer Protocol; `T1048.003`; `T1046` |
| P-18 | **MAC / OUI inconsistencies** | Vendor OUI inconsistent with the device's asserted role; randomised/locally-administered MACs on a wired segment; a new MAC appearing on a controlled port | Rogue or unauthorised device; MAC spoofing; a laptop plugged into an OT switch | `T1200` Hardware Additions (Initial Access); `T0864` Transient Cyber Asset (ICS); `T1036` |
| P-19 | **VLAN tag anomalies** | Unexpected VLAN IDs; double-tagged (QinQ) frames on an access port; frames tagged for a VLAN the port shouldn't carry | VLAN hopping to cross a segmentation boundary | `T1599` Network Boundary Bridging (Defense Impairment TA0112) |
| P-20 | **Spanning-tree / L2 control-plane anomalies** | Unexpected BPDUs, topology-change notifications, a new root bridge election, LLDP/CDP from an unknown device | L2 attack to become on-path, or an unauthorised switch/device introduced | `T1557` AiTM; `T1200` Hardware Additions; `T0830` (ICS) |
| P-21 | **IPv6 control-plane abuse** | Rogue Router Advertisements, spoofed Neighbour Advertisements, unexpected SLAAC prefixes, DHCPv6 from an unknown server, IPv6 enabled where policy says IPv4-only | On-path positioning via IPv6 in an IPv4-monitored network — a classic monitoring blind spot | `T1557.003` DHCP Spoofing (analogous); `T1557.002`; `T1599` Network Boundary Bridging |
| P-22 | **Non-IP EtherTypes** | PROFINET-RT, EtherCAT, GOOSE/SV (IEC 61850), FIP, unexpected proprietary EtherTypes | Real-time OT protocols that bypass IP-layer controls entirely; GOOSE spoofing in substations | `T1692.001` / `T1692.002` Unauthorized Message (ICS); `T0830` Adversary-in-the-Middle (ICS) |
| P-23 | **802.1X / EAPOL activity** | Repeated EAPOL failures; EAP identity probing; a port authenticating with an unexpected identity | NAC bypass attempts; unauthorised device attachment | `T1200` Hardware Additions; `T1078` Valid Accounts |
| P-24 | **Broadcast / multicast volume anomalies** | Broadcast storms; a host sourcing abnormal multicast; unexpected multicast group joins (IGMP) | Discovery sweeps, L2 loops, or DoS; multicast group joins can reveal reconnaissance of ICS multicast services | `T0846.002` Broadcast Discovery, `T0846.003` Multicast Discovery (ICS); `T1498.001` |
| P-25 | **Packet-size distribution shape** | Bimodal or unusually uniform size distributions; a flow whose packets are all exactly the same size; absence of MTU-sized packets in a nominally bulk transfer | Uniform sizes indicate a framed/padded custom protocol or beacon; absence of full-size packets in bulk transfer indicates deliberate rate/size shaping | `T1030` Data Transfer Size Limits; `T1001.001` Junk Data; `T1071` |
| P-26 | **Checksum errors** | Elevated bad-checksum counts not explained by hardware offload | Crafted/injected packets; or simply capture-point offload artefacts — verify before reporting | Evidence-integrity issue first; then `T1659` |

---

## 4. Part B2 — Flow-level characteristics

Properties of assembled bidirectional conversations. This is the most productive level for encrypted traffic, because it survives TLS.

| # | Characteristic | What it looks like | Attack / meaning | ATT&CK / ATLAS |
|---|---|---|---|---|
| F-1 | **Duration distribution tails** | Extreme short and long tails (see A-1, A-2) | Stealth probing; persistence channels | `T1046`, `T1071`, `T1573` |
| F-2 | **Byte-ratio asymmetry** | `bytes_out/bytes_in` inverted relative to the host's role | Exfiltration from a client; or a client acting as a server | `T1041`, `T1048`, `T1567`, `T1090.001` |
| F-3 | **Flow-direction inversion** | The *server*-role host initiates the connection to the client-role host, or an internal host accepts inbound from the internet | Reverse shell; reverse proxy/tunnel; unauthorised listener | `T1219` Remote Access Tools; `T1090` Proxy; `AML.T0072` Reverse Shell; `T1133` External Remote Services |
| F-4 | **Periodicity** | Low-variance inter-flow intervals (see A-5) | Beaconing | `T1071`, `T1029`, `T1020` |
| F-5 | **Fan-out (one → many destinations)** | One source contacting an abnormally large distinct-destination count in a short window | Host/network sweep, worm propagation, or spray | `T1018` Remote System Discovery; `T1046`; `T1110.003` Password Spraying; `T1021` |
| F-6 | **Fan-out (one → many ports)** | One source × one destination × many ports | Port scan | `T1046`; `T0846.001` Port Scan (ICS) |
| F-7 | **Fan-in (many → one)** | Abnormally many sources converging on one destination | DDoS; or a legitimate service that has just become popular; or a staging server collecting data | `T1498.001`, `T1499.002`; `T1074` Data Staged |
| F-8 | **Connection failure ratio** | High ratio of SYNs without SYN-ACK, or ICMP unreachables | Scanning, or a dead service. High failure + high fan-out = scanning; high failure + one target = misconfiguration or DoS | `T1046`, `T1595`, `T1018` |
| F-9 | **Sequential vs. random destination ordering** | Destinations contacted in strict numeric order (`.1, .2, .3 …`) | Automated scanning tool with default settings | `T1046`, `T1595.001` |
| F-10 | **Concurrent-connection count per host** | A single source holding thousands of simultaneous connections | Connection-exhaustion DoS, or a scanner, or a proxy | `T1499.001/.002`; `T1090` |
| F-11 | **Half-open state accumulation** | SYNs greatly exceeding completed handshakes at one target | SYN flood | `T1498.001`, `T1499.001` |
| F-12 | **Request/response amplification ratio** | Small outbound requests producing large inbound responses from many reflectors (DNS ANY, NTP monlist, SSDP, memcached, CLDAP) | Reflection/amplification DDoS — the capture may show *your* host as reflector or as the spoofed victim | `T1498.002` Reflection Amplification |
| F-13 | **Throughput shape over time** | Steady rate-limited plateau vs. bursty maximal | Rate-limited plateau suggests deliberate throttling to stay under a DLP/NetFlow threshold | `T1030` Data Transfer Size Limits; `T1029` |
| F-14 | **Uniform transfer sizes across repeated flows** | Repeated flows carrying near-identical byte totals | Automated chunked exfiltration | `T1030`, `T1020` |
| F-15 | **Off-hours / calendar alignment** | Activity confined to nights, weekends, holidays, or a fixed daily window | Deliberate timing to avoid observation; or a scheduled job | `T1029` Scheduled Transfer; `T1078` Valid Accounts; `T1053` Scheduled Task/Job |
| F-16 | **First-seen flow tuples** | `(src, dst, dport)` combinations never observed in the baseline | The single highest-yield generic hunt signal in a well-baselined estate | Context-dependent; usually `T1021`, `T1071`, `T1046` |
| F-17 | **Zone-edge violations** | Flows crossing a boundary the segmentation policy forbids (IT→OT, DMZ→core, user→management VLAN) | Segmentation failure or active lateral movement; in OT this is often the single most important finding | `T1210` Exploitation of Remote Services; `T1021`; `T0886` Remote Services (ICS); `T0822` External Remote Services (ICS); `T1599` Network Boundary Bridging |
| F-18 | **Round-trip-time distribution** | RTT inconsistent with the destination's apparent location; bimodal RTT within one flow | Traffic being relayed/tunneled; a proxy in path; the "destination" is not where DNS says it is | `T1090.003` Multi-hop Proxy; `T1572` Protocol Tunneling; `T1090.004` Domain Fronting |
| F-19 | **Flow-termination behaviour** | Consistent RST teardown where FIN is normal; flows ending only by timeout | Crafted client; abrupt tool termination; in-path blocking | `T1046`; evidence-integrity check |
| F-20 | **Packets-per-flow vs. bytes-per-packet** | Many packets, tiny payloads, long duration | Interactive shell or keystroke-level channel | `T1021.004` SSH; `T1219`; `AML.T0072` Reverse Shell |
| F-21 | **Flow-rate change points** | A long-stable flow whose behaviour changes abruptly (volume, packet size, interval) | Beacon receiving tasking; stage transition; operator taking manual control | `T1104` Multi-Stage Channels; `T1008` Fallback Channels |
| F-22 | **Simultaneous multi-protocol flows to one destination** | The same peer reached over several unrelated protocols/ports at once | C2 with primary + fallback channels, or a tunnel broker | `T1008` Fallback Channels; `T1571`; `T1090` |
| F-23 | **Long-tail rarity scoring** | `(src, dst, dport)` triples occurring exactly once in a large capture | Rarity is a cheap, powerful prioritiser when baselining is unavailable | Context-dependent |
| F-24 | **Internal staging concentration** | Multiple internal hosts sending unusual volume to one internal host that then egresses | Collection → staging → exfiltration chain | `T1074.001` Local Data Staging / `T1074.002` Remote Data Staging; `T1041`/`T1048` |
---

## 5. Part B3 — Protocol-level characteristics

Protocol semantics carry the most specific evidence. Organised by protocol family.

### 5.1 DNS

DNS is simultaneously the most abused C2/exfil carrier and the richest source of investigative pivots.

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| D-1 | **High NXDOMAIN rate from one host** | Domain-generation algorithm cycling through candidate domains until one resolves | `T1568.002` Domain Generation Algorithms |
| D-2 | **High-entropy / long labels; unusually long FQDNs** | Data encoded into the query name — DNS tunneling or exfiltration | `T1071.004` DNS; `T1048.003`; `T1132.001` |
| D-3 | **Excessive unique subdomains under one parent domain** | Each query carries a chunk of data; the authoritative server is the attacker's | `T1071.004`; `T1041` |
| D-4 | **Abnormal record-type mix** | Heavy `TXT`, `NULL`, `CNAME`, `MX`, or `AAAA` where `A` dominates normally | `T1071.004`; `T1102.001` Dead Drop Resolver |
| D-5 | **Very low TTLs on responses; rapidly rotating A records** | Fast flux infrastructure | `T1568.001` Fast Flux DNS |
| D-6 | **Response records used for arithmetic/decoding rather than connection** | Resolved IP is never contacted, but a derived address is | `T1568.003` DNS Calculation |
| D-7 | **DNS to a resolver other than the sanctioned one** | Bypassing DNS logging and RPZ/sinkhole controls | `T1071.004`; `T1685` Disable or Modify Tools / `T1686` Disable or Modify System Firewall (Defense Impairment TA0112) where a control was actively bypassed |
| D-8 | **DoH / DoT / DoQ usage** | Encrypted DNS defeats query-level inspection; detect by destination (known DoH providers), by TLS ALPN `dot`/`doq`, or by port 853 | `T1071.004`; `T1573.002`; Defense Impairment (TA0112) |
| D-9 | **DNS on a non-53 port, or non-DNS on 53** | Evasion of port-based DNS controls, or tunneling | `T1571`; `T1572` |
| D-10 | **Queries with no subsequent connection to the resolved IP** | Beacon-by-resolution, dead-drop resolver, or a canary/telemetry lookup | `T1102.001`; `T1568` |
| D-11 | **Connections to IPs with no preceding DNS resolution** | Hardcoded C2 address; or resolution happened out of band (DoH) | `T1071`; `T1090` |
| D-12 | **Newly-registered / newly-observed domains** | Adversary infrastructure is typically young | `T1583.001` Acquire Infrastructure: Domains; `T1071` |
| D-13 | **Domains resolving to internal/reserved space** | DNS rebinding, or sinkhole/canary hits | `T1499.004`; `T1090` |
| D-14 | **Reverse-DNS sweep of a subnet** | Host enumeration | `T1018` Remote System Discovery; `T1046` |
| D-15 | **Punycode / homoglyph / typosquat domains** | Phishing and masquerading infrastructure | `T1036` Masquerading; `T1583.001` |
| D-16 | **DNS zone transfer attempts (AXFR/IXFR)** | Bulk enumeration of internal name space | `T1590` Gather Victim Network Information; `T1018` |

### 5.2 TLS and encrypted transport

You cannot read the payload; you can read a great deal of metadata.

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| T-1 | **JA3 / JA3S / JA4 / JA4S client & server fingerprints** | Identifies the TLS *implementation*, not the application. A fingerprint that maps to a Python/Go/.NET runtime on a host that should only run browsers is high-signal; known-malware fingerprints are higher | `T1071.001`; `T1573`; `T1036` Masquerading |
| T-2 | **Fingerprint/user-agent mismatch** | Traffic claims to be Chrome but the TLS stack isn't Chrome's | `T1036`; `T1001.003` Protocol or Service Impersonation |
| T-3 | **Self-signed, expired, or short-validity certificates** | Ad-hoc C2 infrastructure; default tooling certificates (Cobalt Strike, Metasploit, Covenant have known default cert values) | `T1573.002`; `T1587.003`/`T1588.004` Digital Certificates |
| T-4 | **Certificate subject/issuer anomalies** | Blank, nonsense, or default CN/O fields; certificates reused across unrelated IPs | `T1573.002`; `T1588.004` |
| T-5 | **SNI ≠ certificate CN/SAN; or SNI ≠ HTTP Host header** | Domain fronting — the TLS handshake names a reputable CDN host while the inner request targets another | `T1090.004` Domain Fronting |
| T-6 | **Absent SNI, or Encrypted Client Hello (ECH)** | Deliberate concealment of the destination hostname | `T1090.004`; `T1573`; Stealth (TA0005) |
| T-7 | **Obsolete protocol versions (SSLv3, TLS 1.0/1.1) or weak ciphers (RC4, 3DES, NULL, EXPORT)** | Legacy debt, *or* an active downgrade to enable interception/decryption | `T1689` Downgrade Attack (Defense Impairment TA0112); `T1600` Weaken Encryption |
| T-8 | **Version/cipher downgrade mid-negotiation; renegotiation floods** | Forced downgrade; renegotiation DoS | `T1689`; `T1499.002` |
| T-9 | **A new root/intermediate CA appearing in chains** | TLS interception device — sanctioned, or an adversary's | `T1553.004` Install Root Certificate (Defense Impairment); `T1557` |
| T-10 | **Non-TLS traffic on 443 / TLS on unusual ports** | Custom protocol impersonating HTTPS, or tunneling | `T1001.003`; `T1571`; `T1572` |
| T-11 | **Abnormal session-resumption or ticket behaviour** | Custom client implementation; or fingerprint evasion | `T1036` |
| T-12 | **TLS record-size and direction patterns** | Even encrypted, request/response sizing reveals beacon shape and interactivity | `T1071`; `T1573` |
| T-13 | **QUIC / HTTP-3 usage where unexpected** | UDP-based transport that many inspection stacks do not parse | `T1071.001`; `T1572`; Stealth (TA0005) |

### 5.3 HTTP / web

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| H-1 | **Anomalous or absent User-Agent; UA inconsistent with host inventory** | Tooling and custom implants; `curl`, `python-requests`, `Go-http-client`, `PowerShell` on a user workstation | `T1071.001`; `T1036` |
| H-2 | **High-entropy URI paths, or base64/hex in path, query, or cookie** | Encoded C2 tasking or exfiltration | `T1071.001`; `T1132.001`; `T1041` |
| H-3 | **POST-heavy traffic to a single endpoint with uniform sizes** | Beacon check-in with data upload | `T1071.001`; `T1041`; A-5 |
| H-4 | **Requests without a Referer chain; no supporting asset requests** | Machine-generated, not browser-generated: a real page load pulls CSS/JS/images | `T1071.001` |
| H-5 | **Unusual header ordering, casing, or non-standard headers** | Implementation fingerprint of a non-browser client | `T1036`; `T1071.001` |
| H-6 | **Unusual methods (`PUT`, `DELETE`, `PROPFIND`, `TRACE`, `CONNECT`)** | WebDAV abuse, proxying via `CONNECT`, or exploitation | `T1090`; `T1071.001`; `T1190` |
| H-7 | **Web-service C2 destinations** | Pastebin/Gist/Discord/Telegram/Slack webhooks/cloud storage used as the channel | `T1102.001/.002/.003` Web Service; `T1567.001/.002/.003/.004` |
| H-8 | **WebSocket upgrades to unexpected destinations** | Long-lived bidirectional channel that looks like HTTP | `T1071.001`; `T1102.002`; A-2 |
| H-9 | **Directory/parameter brute force** | Bursts of 404s across wordlist-shaped paths | `T1595.003` Wordlist Scanning |
| H-10 | **Exploitation strings in requests** | See A-6 | `T1190`; `T1210`; `T1659` |
| H-11 | **Web shell interaction pattern** | Repeated POSTs to a single, oddly-named file, with variable-length responses and no supporting assets | `T1505.003` Server Software Component: Web Shell (Persistence); `T1071.001` |
| H-12 | **HTTP request smuggling / desync artefacts** | Conflicting `Content-Length` and `Transfer-Encoding` headers | `T1190`; Stealth (TA0005) |
| H-13 | **Redirect chains through unrelated domains** | Traffic distribution systems, malvertising, or C2 redirectors | `T1090.003` Multi-hop Proxy; `T1608` Stage Capabilities |
| H-14 | **Plaintext credentials/tokens in URLs or headers** | Credential exposure and harvesting opportunity | `T1040`; `T1552.001` |

### 5.4 Windows / Active Directory protocols (SMB, Kerberos, LDAP, NTLM, DCERPC)

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| W-1 | **SMBv1 / SMB signing disabled / anonymous (null) sessions** | Legacy exposure enabling relay and known exploit families | `T1021.002`; `T1557.001`; `T1210` |
| W-2 | **Access to `ADMIN$`, `C$`, `IPC$` from a non-admin host** | Remote execution and lateral tool transfer | `T1021.002` SMB/Windows Admin Shares; `T1570` |
| W-3 | **Named-pipe usage: `svcctl`, `atsvc`, `winreg`, `psexesvc`, `paexec`, `remcom`** | Remote service creation / scheduled task / registry — the PsExec-family execution pattern | `T1021.002`; `T1569.002` Service Execution; `T1053.005` Scheduled Task |
| W-4 | **DCERPC `DRSUAPI` / `DRSGetNCChanges` from a non-DC** | DCSync — replication of credential material | `T1003.006` OS Credential Dumping: DCSync |
| W-5 | **DCERPC `EFSRPC` (`EfsRpcOpenFileRaw`), `MS-RPRN`, `MS-DFSNM` calls to a host** | Authentication-coercion families (PetitPotam, PrinterBug, DFSCoerce) used to feed a relay | `T1187` Forced Authentication; `T1557.001` |
| W-6 | **Enumeration over SMB: `srvsvc` share enumeration, mass `NetShareEnum`** | Share discovery preceding collection | `T1135` Network Share Discovery |
| W-7 | **LDAP queries with broad scope / recursive group expansion / `objectClass=*`** | Directory enumeration — BloodHound/SharpHound-style collection | `T1087.002` Domain Account Discovery; `T1069.002` Domain Groups; `T1482` Domain Trust Discovery; `T1615` Group Policy Discovery |
| W-8 | **LDAP simple bind over cleartext 389** | Credentials on the wire | `T1040`; `T1552.001` |
| W-9 | **Kerberos `TGS-REQ` with etype 23 (RC4-HMAC) in an AES domain; many SPNs requested rapidly** | Kerberoasting | `T1558.003` |
| W-10 | **Kerberos `AS-REQ` without pre-authentication** | AS-REP roasting | `T1558.004` |
| W-11 | **TGS usage without a preceding AS exchange from that source** | Pass-the-ticket / forged ticket | `T1550.003`; `T1558.001/.002` |
| W-12 | **Tickets with anomalous lifetimes or missing/invalid PAC** | Golden/silver ticket | `T1558.001`, `T1558.002` |
| W-13 | **NTLM where Kerberos is expected; NTLM to many targets from one source** | Pass-the-hash, or relay | `T1550.002`; `T1557.001` |
| W-14 | **NTLMv1 negotiated / session security downgraded** | Deliberate downgrade to enable cracking or relay | `T1689` Downgrade Attack; `T1600` Weaken Encryption |
| W-15 | **LLMNR / NBT-NS / mDNS responses from a host that is not the owner** | Name-resolution poisoning to capture authentication | `T1557.001` Name Resolution Poisoning and SMB Relay |
| W-16 | **Mass SMB reads across many shares in a short window** | Collection prior to exfiltration | `T1039` Data from Network Shared Drive; `T1213`; `T1074` |
| W-17 | **Mass SMB writes with changed extensions and high-entropy content; deletion of shadow copies / backup shares** | Ransomware encryption in progress | `T1486` Data Encrypted for Impact; `T1490` Inhibit System Recovery; `T1485` Data Destruction |
| W-18 | **WinRM (5985/5986) or WMI/DCOM (135 + ephemeral) from unexpected sources** | Remote execution channel | `T1021.006` WinRM; `T1021.003` DCOM; `T1047` WMI |
| W-19 | **Unexpected DC replication traffic, or a new host behaving as a DC** | Rogue domain controller | `T1207` Rogue Domain Controller (Defense Impairment TA0112) |

### 5.5 Remote access and administration

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| R-1 | **SSH on non-22, or SSH version/banner anomalies** | Relocated service; non-standard client (paramiko, libssh) | `T1021.004`; `T1571`; `T1036` |
| R-2 | **SSH port forwarding / dynamic (SOCKS) forwarding indicators** | Tunneling other protocols through an approved channel; pivoting | `T1572` Protocol Tunneling; `T1090.001` Internal Proxy |
| R-3 | **RDP to/from unexpected hosts; RDP certificate change; non-3389 RDP** | Lateral movement; possible AiTM on the RDP session | `T1021.001`; `T1557` |
| R-4 | **RDP virtual channels for clipboard/drive redirection carrying volume** | Data movement over the RDP session | `T1570`; `T1041` |
| R-5 | **VNC (5900+) traffic, especially unauthenticated** | Remote control, often unmanaged | `T1021.005` VNC |
| R-6 | **RMM / remote-support tools (TeamViewer, AnyDesk, ScreenConnect, Splashtop, Atera, ngrok, Cloudflare Tunnel, IDE remote tunnels)** | Adversaries increasingly use legitimate RMM rather than malware; also the most common initial-access persistence in current intrusions | `T1219` Remote Access Tools (`.001` IDE Tunneling, `.002` Remote Desktop Software, `.003` Remote Access Hardware); `T1133` External Remote Services |
| R-7 | **Telnet (23) or rlogin anywhere** | Cleartext administration; common on OT and network gear | `T1040`; `T1078`; `T0886` (ICS) |
| R-8 | **SNMP with default/guessed community strings; bulk MIB walks; SNMP writes** | Device enumeration and configuration theft or modification | `T1602.001` SNMP (MIB Dump); `T1046`; `T1601` Modify System Image |
| R-9 | **TFTP to/from network or OT devices** | Configuration and firmware transfer — legitimate for maintenance, ideal for attackers | `T1602.002` Network Device Configuration Dump; `T1105`; `T1693` Modify Firmware (ICS) |
| R-10 | **Management-plane access from a user VLAN** | Segmentation violation into the management zone | `T1599` Network Boundary Bridging; `T1021` |

### 5.6 File transfer, mail, and messaging

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| M-1 | **FTP/FTPS/TFTP where policy mandates SFTP; cleartext `USER`/`PASS`** | Credential exposure and uncontrolled transfer | `T1071.002`; `T1048.003`; `T1040` |
| M-2 | **Anonymous FTP `STOR` of executables, or `RETR` of archives** | Ingress tooling / egress data | `T1105`; `T1048.003` |
| M-3 | **SMTP to non-corporate relays; large attachments; base64 blobs** | Exfiltration by mail | `T1071.003` Mail Protocols; `T1048.003`; `T1567` |
| M-4 | **Autoforward/relay patterns; unusual MAIL FROM domains** | Collection and exfiltration of mail | `T1114` Email Collection |
| M-5 | **Messaging-platform APIs (Telegram, Discord, Slack webhooks) from servers** | Common modern C2 and exfil channel | `T1102.002` Bidirectional Communication; `T1567.004` Exfiltration Over Webhook |
| M-6 | **Publish/subscribe brokers (MQTT, AMQP, Kafka, NATS) reached from unexpected clients** | Pub/sub as a C2 carrier; also an OT data path | `T1071.005` Publish/Subscribe Protocols |
| M-7 | **NFS/WebDAV mounts from unexpected sources** | Alternative file access path around SMB monitoring | `T1039`; `T1021` |

### 5.7 Core network services

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| N-1 | **Rogue DHCP server / unexpected DHCP OFFERs** | On-path positioning by controlling gateway and DNS | `T1557.003` DHCP Spoofing |
| N-2 | **DHCP starvation (flood of DISCOVERs with random MACs)** | Precursor to rogue DHCP; also a DoS | `T1557.003`; `T1498` |
| N-3 | **NTP to unsanctioned servers; large time skew; monlist queries** | Time manipulation undermines log correlation and Kerberos; monlist indicates amplification abuse | `T1498.002`; Defense Impairment (TA0112) generally |
| N-4 | **mDNS / SSDP / WS-Discovery / LLMNR sweeps** | Service discovery, often the first act of a tool landing on a segment | `T1046`; `T1018`; `T0846.002/.003` (ICS) |
| N-5 | **Routing-protocol anomalies (unexpected OSPF/BGP/HSRP/VRRP speakers)** | Route injection to become on-path; first-hop redundancy hijack | `T1557`; `T1599` Network Boundary Bridging |
| N-6 | **ICMP redirects, unexpected router advertisements** | Traffic redirection | `T1557` |
| N-7 | **Unexpected proxy / PAC file activity (WPAD)** | WPAD hijack for credential capture and traffic control | `T1557.001`; `T1090` |
| N-8 | **Certificate revocation (OCSP/CRL) absence** | Client deliberately skipping revocation checks | `T1553` Subvert Trust Controls (Defense Impairment) |
### 5.8 Industrial control / OT protocols

OT traffic is unusually *predictable* — fixed masters, fixed polling cycles, a small closed set of function codes. That predictability makes deviation detection far more powerful in OT than in IT. The governing question is always: **is this the right source, sending the right function, at the right time, in an approved change window?**

**Cross-protocol OT indicators**

| # | Characteristic | Meaning | ATT&CK for ICS |
|---|---|---|---|
| O-1 | **A new master / unexpected source issuing control-class functions** | Rogue master injecting commands the HMI never sent | `T0848` Rogue Master; `T1692.001` Unauthorized Message: Command Message |
| O-2 | **Write functions where the baseline shows only reads** | Unauthorised process manipulation | `T0836` Modify Parameter; `T1692.001`; `T0831` Manipulation of Control |
| O-3 | **Falsified or replayed telemetry toward the HMI/historian** | Operator's view of the process is wrong — masks a physical attack | `T1692.002` Unauthorized Message: Reporting Message; `T0832` Manipulation of View; `T0829` Loss of View |
| O-4 | **Polling-cycle deviation** (period change, missed cycles, cycle from a new source) | Injected traffic, a device under load, or a communications block | `T1691` Block Operational Technology Message; `T1695` Block Communications; `T0814` Denial of Service |
| O-5 | **Program/logic download or upload outside a change window** | Controller logic being altered or stolen | `T0843` Program Download (`.001` Download All, `.002` Online Edit, `.003` Program Append); `T0845` Program Upload |
| O-6 | **Operating-mode change commands (RUN → STOP/PROGRAM/REMOTE)** | Disabling protective logic or halting the process | `T0858` Change Operating Mode; `T0813` Denial of Control |
| O-7 | **Restart / shutdown / firmware-update-mode commands** | Availability impact and a window for firmware tampering | `T0816` Device Restart/Shutdown; `T0800` Activate Firmware Update Mode; `T1693` Modify Firmware |
| O-8 | **Alarm configuration writes or alarm suppression** | Hiding the effect of an attack from operators | `T0878` Alarm Suppression; `T0838` Modify Alarm Settings |
| O-9 | **Enumeration of device identity, tags, or points** | Reconnaissance to build a process model before acting | `T0888` Remote System Information Discovery; `T0861` Point & Tag Identification; `T0846` Remote System Discovery (`.001` Port Scan, `.002` Broadcast Discovery, `.003` Multicast Discovery) |
| O-10 | **Rapid alternating writes to an I/O point** | Forcing outputs / exercising actuators to cause damage | `T0806` Brute Force I/O; `T0835` Manipulate I/O Image |
| O-11 | **Engineering-workstation project file transfer** | Tampered project file becomes persistent on next download | `T0873` Project File Infection |
| O-12 | **Malformed / fuzzed OT protocol frames** | Many controllers fault on malformed input; low volume, high impact | `T0814` Denial of Service; `T0816`; `T0820` Exploitation for Evasion |
| O-13 | **Traffic from IT/enterprise or external space into the OT zone** | The boundary crossing that precedes nearly every OT incident | `T0886` Remote Services; `T0822` External Remote Services; `T0883` Internet Accessible Device; `T0866` Exploitation of Remote Services |
| O-14 | **Default, hardcoded, or anonymous device credentials in use** | Trivial access to controllers and HMIs | `T1694.001` Default Credentials; `T1694.002` Hardcoded Credentials; `T0859` Valid Accounts |
| O-15 | **A transient device (laptop, USB-tethered, vendor asset) appearing on the OT segment** | Unmanaged asset introduced into the process network | `T0864` Transient Cyber Asset; `T0847` Replication Through Removable Media |
| O-16 | **Mass historian/OPC read of process data** | Theft of operational information / process intellectual property | `T0882` Theft of Operational Information; `T0802` Automated Collection; `T0811` Data from Information Repositories |

**Protocol-specific tells**

| Protocol (port) | High-signal observations |
|---|---|
| **Modbus/TCP (502)** | Write function codes `05` (Write Single Coil), `06` (Write Single Register), `15/0x0F` (Write Multiple Coils), `16/0x10` (Write Multiple Registers) from a non-master. Function `08` (Diagnostics) sub-code "Restart Communications Option". Function `43/0x2B` (Read Device Identification) = fingerprinting. Unit-ID sweeps 0–247 = enumeration. Exception-response floods. Modbus has **no authentication whatsoever** — source legitimacy is the only control the network can express. |
| **S7comm / S7comm-plus (102, via COTP/TPKT)** | PLC STOP / RUN job functions; block download (`Download Block`) and upload (`Upload Block`); `Read SZL` system-state list queries (reconnaissance); TSAP/rack-slot enumeration during COTP connection setup; S7comm-plus session anomalies. Maps to `T0858`, `T0843`, `T0845`, `T0888`. |
| **DNP3 (20000)** | Function `13` Cold Restart, `14` Warm Restart, `21` Disable Unsolicited Responses (blinds the master), `18` Direct Operate, `05` Operate, `02` Write. Unsolicited responses from an unexpected outstation. Maps to `T0816`, `T0878`, `T1691`, `T1692.001`. |
| **IEC 60870-5-104 (2404)** | Type IDs `45–51` (single/double command, setpoint), `100` Interrogation, `105` Reset process, `103` Clock sync abuse. Commands from a non-controlling station. |
| **OPC UA (4840)** | `SecurityPolicy=None` or anonymous `UserIdentityToken`; certificate mismatch or self-signed application instance certs; full `Browse` of the address space (reconnaissance); `Call` on methods; subscription creation with abnormal publish intervals; write services on nodes normally read-only. Maps to `T0871` Execution through API, `T0861`, `T0859`. |
| **EtherNet/IP + CIP (44818 TCP / 2222 UDP)** | `List Identity` broadcast sweeps; CIP `Set_Attribute_Single` writes; forward-open to unexpected connection points; class-1 implicit I/O from a new source. Maps to `T0846.002`, `T0836`. |
| **BACnet (47808/UDP)** | `Who-Is` / `I-Am` sweeps (enumeration); `WriteProperty` / `WritePropertyMultiple` from unexpected sources; `ReinitializeDevice`; `DeviceCommunicationControl` (silences a device — a direct DoS primitive). Maps to `T0846.002`, `T0836`, `T0816`, `T1695`. |
| **IEC 61850 GOOSE / Sampled Values (L2, non-IP)** | State-number/sequence-number regressions or jumps (replay or spoofed publisher); a new publisher MAC for an existing GOOSE control block; publication interval anomalies. Maps to `T1692.002`, `T0830`. |
| **PROFINET (L2 + UDP)** | DCP `Identify All` sweeps; DCP `Set` of device name/IP (hijacking device identity); alarm frames. Maps to `T0846.002`, `T0836`. |

> **OT analysis principle:** in IT you hunt for anomalies against a noisy baseline. In OT you hunt for *any deviation at all* from a tightly-specified allow-list of (source, destination, protocol, function code, cadence). Build that allow-list first; everything outside it is a finding.

### 5.9 AI / ML system protocols — MITRE ATLAS

Where the environment hosts model-serving, training, RAG, or agentic infrastructure, the network carries a distinct class of attack that ATT&CK does not cover. These are the network-observable subset of ATLAS.

| # | Characteristic | Meaning | ATLAS |
|---|---|---|---|
| AI-1 | **High-volume, systematic queries to an inference endpoint from one client** — often with inputs that sweep a feature space or are near-duplicates | Model extraction / distillation: reconstructing the model from its outputs | `AML.T0024.002` Extract AI Model; `AML.T0040` AI Model Inference API Access; `AML.T0048.004` AI Intellectual Property Theft |
| AI-2 | **Repeated near-identical queries with small perturbations, and responses being harvested** | Black-box adversarial-example search | `AML.T0043.001` Craft Adversarial Data: Black-Box Optimization; `AML.T0042` Verify Attack |
| AI-3 | **Probing patterns designed to elicit confidence scores / logits on specific records** | Membership inference — determining whether a record was in the training set | `AML.T0024.000` Infer Training Data Membership |
| AI-4 | **Query patterns aimed at reconstructing training inputs** | Model inversion | `AML.T0024.001` Invert AI Model |
| AI-5 | **Prompt-injection strings in request payloads** to an LLM API (`/v1/chat/completions`, gRPC, MCP/JSON-RPC) | Direct prompt injection | `AML.T0051.000` LLM Prompt Injection: Direct |
| AI-6 | **Injected instructions inside content the system retrieves** — web pages, documents, emails, or vector-store records fetched by a RAG pipeline | Indirect prompt injection; the payload arrives on a *different* flow than the attacker's | `AML.T0051.001` Indirect; `AML.T0070` RAG Poisoning; `AML.T0066` Retrieval Content Crafting |
| AI-7 | **Jailbreak scaffolds and role-play framings in payloads** | Guardrail bypass | `AML.T0054` LLM Jailbreak |
| AI-8 | **Encoded / obfuscated prompt content** — base64, unicode tag characters, zero-width joiners, homoglyphs, ROT/leetspeak | Evading prompt filters and payload inspection | `AML.T0068` LLM Prompt Obfuscation |
| AI-9 | **System-prompt extraction attempts and responses containing system instructions** | Disclosure of proprietary instructions and tool definitions | `AML.T0056` Extract LLM System Prompt; `AML.T0069.002` Discover LLM System Information: System Prompt |
| AI-10 | **Sensitive data appearing in model responses** | Training-data or context leakage | `AML.T0057` LLM Data Leakage |
| AI-11 | **Model artefacts fetched from unvetted hosts** (`.pt`, `.pkl`, `.ckpt`, `.safetensors`, `.gguf`, `.onnx`, `.h5`) — especially pickle formats | Supply-chain compromise; pickle deserialisation executes arbitrary code on load | `AML.T0010.003` AI Supply Chain Compromise: Model; `AML.T0011.000` User Execution: Unsafe AI Artifacts; `AML.T0002.001` Acquire Public AI Artifacts: Models |
| AI-12 | **Training data or dataset archives pulled from unexpected sources** | Data poisoning at the source | `AML.T0010.002` Supply Chain: Data; `AML.T0020` Poison Training Data; `AML.T0019` Publish Poisoned Datasets |
| AI-13 | **Writes to a vector database / embedding store from an unauthorised source** (Qdrant 6333, Milvus 19530, Weaviate 8080, Chroma 8000, pgvector) | Poisoning the retrieval corpus — persistent, and it survives model updates | `AML.T0070` RAG Poisoning; `AML.T0059` Erode Dataset Integrity |
| AI-14 | **Agent tool-invocation traffic (MCP, JSON-RPC, function-calling) reaching destinations outside the agent's expected tool set** | An injected instruction has caused the agent to act; the network is often the only place this is visible | `AML.T0053` AI Agent Tool Invocation; `AML.T0051` |
| AI-15 | **Outbound connections from a training cluster or inference host that should have no egress** | Exfiltration of artefacts, or a compromised training pipeline | `AML.T0025` Exfiltration via Cyber Means; `AML.T0035` AI Artifact Collection |
| AI-16 | **Reverse shell from an AI/ML host or agent runtime** | Post-exploitation of the AI stack | `AML.T0072` Reverse Shell (Command and Control, `AML.TA0014`) |
| AI-17 | **Sustained expensive inference load from one client** | Cost inflation, or denial of service by resource exhaustion | `AML.T0034` Cost Harvesting; `AML.T0029` Denial of AI Service |
| AI-18 | **High-volume junk submissions to a system that learns from input** | Feedback-loop poisoning / integrity erosion | `AML.T0046` Spamming AI System with Chaff Data; `AML.T0031` Erode AI Model Integrity |
| AI-19 | **Scanning of AI-specific paths** (`/v1/models`, `/docs`, `/openapi.json`, `/health`, `/.well-known/ai-plugin.json`, MLflow and Ray dashboards, TensorBoard, notebook servers) | Discovery of AI assets and their interfaces | `AML.T0006` Active Scanning; `AML.T0007` Discover AI Artifacts; `AML.T0013` Discover AI Model Ontology; `AML.T0014` Discover AI Model Family |
| AI-20 | **API keys / bearer tokens to AI services in cleartext** | Credential exposure enabling model access and cost abuse | `AML.T0055` Unsecured Credentials; `AML.T0012` Valid Accounts |
| AI-21 | **Exposed model-serving or orchestration ports** (Ollama 11434, vLLM/TGI 8000, MLflow 5000, Ray 8265/10001, Jupyter 8888, TensorBoard 6006) reachable from user or internet zones | Unauthenticated model access — a growing real-world exposure class | `AML.T0040` AI Model Inference API Access; `AML.T0047` AI-Enabled Product or Service; `AML.T0049` Exploit Public-Facing Application |
| AI-22 | **Adversarially-perturbed inputs submitted to a classifier/detector** (images, network data, documents) | Evading an AI-based control — including an AI-based security control | `AML.T0015` Evade AI Model (Initial Access / Defense Evasion / Impact); `AML.T0043` Craft Adversarial Data |

---

## 6. Part B4 — IP / host-level characteristics

Properties of endpoints and their external counterparties, aggregated across all their flows.

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| I-1 | **Newly-observed external IP / ASN / domain** | Adversary infrastructure is new by definition. Rank all external peers by first-seen date | `T1583` Acquire Infrastructure; `T1584` Compromise Infrastructure; `T1071` |
| I-2 | **Peer registration age (domain age, IP allocation recency)** | Domains registered within 30 days are disproportionately malicious | `T1583.001` Domains |
| I-3 | **Hosting characteristics: bulletproof hosting, VPS ranges, residential proxies, Tor exit nodes, cloud-function egress ranges** | Deliberate infrastructure obfuscation | `T1090.003` Multi-hop Proxy; `T1665` Hide Infrastructure; `T1583` |
| I-4 | **Geolocation inconsistent with business need** | Traffic to countries where the organisation has no operations | Contextual; supports `T1041`, `T1048`, `T1071` |
| I-5 | **Threat-intelligence matches (IP, domain, JA3/JA4, certificate hash, URL)** | Direct known-bad correlation — high confidence, low coverage | Technique depends on the intel |
| I-6 | **Bare-IP connections with no preceding DNS lookup** | Hardcoded C2, or resolution performed over DoH | `T1071`; `T1568`; `T1090` |
| I-7 | **DNS-to-connection latency anomalies** | Connections long after resolution (cached list of hardcoded targets) or before it (out-of-band resolution) | `T1568`; `T1102.001` |
| I-8 | **Role deviation** — a client-role host accepting inbound connections, serving files, or resolving names for others | The host has become a server, proxy, or relay | `T1090.001` Internal Proxy; `T1219`; `T1505` Server Software Component |
| I-9 | **Peer-group deviation** — this host's protocol mix, destination count, or volume differs sharply from identically-provisioned peers | The most reliable generic host-level signal in a homogeneous estate | Contextual |
| I-10 | **Protocol-profile change over time** | A host that suddenly starts speaking protocols it never used | Contextual; often `T1046`, `T1021` |
| I-11 | **External destination cardinality** | A host contacting far more distinct external endpoints than its peers | `T1046`; `T1071`; also P2P/updater noise |
| I-12 | **Dual-homed / multi-zone hosts** | A host bridging two segments is the segmentation control's weakest point | `T1599` Network Boundary Bridging (Defense Impairment TA0112); `T1090.001` |
| I-13 | **New MAC/IP bindings; IP conflicts; unknown OUIs** | Rogue or unmanaged devices | `T1200` Hardware Additions; `T0864` Transient Cyber Asset (ICS) |
| I-14 | **Unexpected IPv6 activity on an IPv4-managed network** | Monitoring blind spot exploited deliberately | `T1599`; Stealth (TA0005) |
| I-15 | **Hosts contacting known exfiltration-friendly services** (paste sites, code repos, cloud storage, file-drop, webhook endpoints) | Egress channel selection | `T1567.001/.002/.003/.004`; `T1102` |
| I-16 | **Hosts contacting known C2-as-a-service or tunneling brokers** (ngrok, Cloudflare Tunnel, localtunnel, serveo, Tailscale/ZeroTier where unsanctioned) | Ingress tunnel that defeats perimeter controls entirely | `T1090`; `T1219`; `T1572`; `T1133` |
| I-17 | **Multiple internal hosts sharing one external peer, one interval, and one TLS fingerprint** | Campaign-level correlation — the strongest evidence that a beacon is malicious | `T1071`; `T1573` |
| I-18 | **A host that begins scanning shortly after receiving a file or completing an authentication** | The behavioural sequence of a fresh compromise | `T1105` → `T1046` → `T1021` |
| I-19 | **Asset-criticality overlay** — the same anomaly on a domain controller, historian, jump host, PLC, or model registry is a different severity than on a print server | Prioritisation, not detection | Contextual |
| I-20 | **Hosts with no expected egress that egress at all** (OT devices, backup targets, HSMs, training clusters, air-gap-adjacent systems) | Binary, extremely high-signal: these hosts should have zero internet flows | `T0822`/`T0883` (ICS); `AML.T0025`; `T1041` |
---

## 7. Part B5 — Connection / session-level characteristics

Properties of the *relationship* between two endpoints over time, and of the communication graph as a whole. This level is where lateral movement and campaign structure become visible.

| # | Characteristic | Meaning | ATT&CK / ATLAS |
|---|---|---|---|
| C-1 | **Novel edges in the communication graph** | A `(src → dst)` pair that has never communicated before. In a stable enterprise, most novel internal edges are either change-management events or lateral movement | `T1021` Remote Services; `T1210`; `T1570` |
| C-2 | **Movement chains** — A→B, then B→C, then C→D within a short window, each hop using the same protocol and credential pattern | Sequential lateral movement. Detect by building a temporal graph and searching for directed paths with short inter-hop latency | `T1021` (+ subs); `T1570` Lateral Tool Transfer; `T1550` Use Alternate Authentication Material |
| C-3 | **Graph-centrality change** — a host that suddenly becomes a hub (high out-degree) or a bridge (high betweenness) | Pivot host / internal proxy / staging point | `T1090.001` Internal Proxy; `T1074.002` Remote Data Staging |
| C-4 | **Authentication-source breadth** — one credential authenticating to an unusually wide set of destinations | Credential reuse after theft; or spraying | `T1078`; `T1550.002/.003`; `T1110.003` |
| C-5 | **Session-time anomalies** — first-ever off-hours session; sessions during holidays; sessions that persist across the user's logoff | Timing chosen to avoid observation, or automation masquerading as a user | `T1078`; `T1029` |
| C-6 | **Interactivity signature** — small packets with human-scale, irregular inter-arrival times inside an otherwise idle session | A human is typing. Distinguishes a hands-on-keyboard operator session from an automated one — often the difference between commodity malware and a targeted intrusion | `T1021.001/.004/.005`; `T1219`; `AML.T0072` |
| C-7 | **Automation signature** — perfectly regular packet timing, uniform sizes, no idle-thinking gaps | Scripted tooling | `T1020` Automated Exfiltration; `T1059`; `T1053` |
| C-8 | **Concurrent sessions from incompatible sources for one identity** | Credential sharing or theft; "impossible travel" at network scale | `T1078` Valid Accounts |
| C-9 | **Session-parameter changes mid-connection** — source port, TTL, TCP options, or TLS fingerprint changing within a logical session | Session hijack, or an in-path device rewriting traffic | `T1557` Adversary-in-the-Middle; `T1659` Content Injection |
| C-10 | **Re-authentication / ticket-renewal frequency anomalies** | Ticket replay, or a tool that re-authenticates per action rather than reusing a session | `T1550.003`; `T1558` |
| C-11 | **Connection persistence across reboots and network changes** | A channel that survives host restart implies host-level persistence | `T1547`/`T1543` persistence families; `T1205.002` Socket Filters |
| C-12 | **Zone-crossing matrix violations** | Any session on a zone edge that the policy matrix marks as forbidden | `T1599`; `T1021`; `T0886`/`T0822` (ICS) |
| C-13 | **Service-relationship inversion** — a client that has only ever been a TLS client suddenly presenting a server certificate | Listener installed on the host | `T1505`; `T1219`; `T1571` |
| C-14 | **Repeated failed sessions followed by one success** | Brute force that worked. The *transition point* is the critical timestamp for the investigation | `T1110`; `T1078` |
| C-15 | **Session establishment without preceding discovery** | The attacker already knew the target — implies prior reconnaissance, insider knowledge, or a stolen inventory | Supports `T1590`/`T1591` (Reconnaissance) |
| C-16 | **Sessions to decommissioned or non-existent assets** | Stale configuration — or an attacker working from an outdated inventory they stole | Contextual |
| C-17 | **Rare-triple scoring** — `(src, dst, dport)` combinations in the bottom percentile of frequency | Cheap prioritiser that works without a historical baseline | Contextual |
| C-18 | **Bidirectional-flow pairing anomalies** — a response with no matching request, or vice versa | Injected traffic, asymmetric routing, or capture gaps (check Stage 0 first) | `T1659`; evidence integrity |
| C-19 | **Protocol-sequence violations within a session** — steps taken out of order, or states skipped | Custom client, exploitation, or a tunnel wearing the protocol as a costume | `T1001.003` Protocol or Service Impersonation; `T1190` |
| C-20 | **Post-compromise behavioural sequence** — auth success → share enumeration → file write → service creation → new outbound connection, within minutes | The composite pattern is far more reliable than any single element. Detect as an ordered sequence, not a set | `T1078` → `T1135` → `T1021.002` → `T1569.002` → `T1071` |

---

## 8. Part C — Consolidated technique mapping

Reverse index: from technique to the observables that evidence it. Use this when writing up findings, to check you have collected all available corroboration for a technique you intend to assert.

### 8.1 ATT&CK Enterprise (v19.2)

| Technique | Tactic | Primary network observables |
|---|---|---|
| `T1595` Active Scanning (`.001` IP Blocks, `.002` Vulnerability, `.003` Wordlist) | Reconnaissance (TA0043) | External fan-out, high SYN-failure ratio, sequential targets, 404 bursts |
| `T1590` Gather Victim Network Information | Reconnaissance | DNS AXFR attempts, reverse-DNS sweeps, WHOIS-adjacent lookups |
| `T1583` / `T1584` Acquire / Compromise Infrastructure | Resource Development (TA0042) | Newly-registered domains, young ASNs, certificate reuse across IPs |
| `T1608` Stage Capabilities | Resource Development | Payload-hosting URLs that victims fetch from |
| `T1190` Exploit Public-Facing Application | Initial Access (TA0001) | Exploit strings in requests, anomalous responses, post-request behaviour change |
| `T1133` External Remote Services | Initial Access | Inbound VPN/RDP/SSH from unexpected sources; tunnel brokers |
| `T1200` Hardware Additions | Initial Access | New MAC/OUI, 802.1X anomalies, unexpected DHCP clients |
| `T1659` Content Injection | Initial Access / C2 | TTL/IP-ID inconsistency, duplicate sequence numbers, injected responses |
| `T1203` / `T1059` Exploitation for Client Execution / Command and Scripting Interpreter | Execution (TA0002) | Malicious document transfer; command strings in payloads |
| `T1047` Windows Management Instrumentation | Execution | DCERPC 135 + ephemeral to unexpected hosts |
| `T1569.002` Service Execution | Execution | `svcctl` named pipe after admin-share write |
| `T1053` Scheduled Task/Job | Execution / Persistence | `atsvc` pipe; periodic network activity aligned to a schedule |
| `T1505.003` Web Shell | Persistence (TA0003) | Repeated POSTs to a single odd path, variable responses, no asset requests |
| `T1078` Valid Accounts (`.001`–`.004`) | Initial Access / Persistence / Priv Esc / Stealth | Successful auth with anomalous source, time, breadth, or target |
| `T1110` Brute Force (`.001` Guessing, `.003` Spraying, `.004` Stuffing) | Credential Access (TA0006) | Auth failure volume and account/target breadth ratios |
| `T1558` Steal or Forge Kerberos Tickets (`.001`–`.005`) | Credential Access | RC4 TGS-REQ bursts, AS-REQ without pre-auth, anomalous ticket lifetimes |
| `T1550` Use Alternate Authentication Material (`.002` PtH, `.003` PtT) | Lateral Movement / Defense Impairment | NTLM where Kerberos expected; TGS without AS; breadth of reuse |
| `T1557` Adversary-in-the-Middle (`.001` Name Resolution Poisoning and SMB Relay, `.002` ARP Cache Poisoning, `.003` DHCP Spoofing, `.004` Evil Twin) | Credential Access / Collection | Rogue LLMNR/NBT-NS/mDNS answers, ARP flaps, rogue DHCP, duplicate responses |
| `T1187` Forced Authentication | Credential Access | EFSRPC/MS-RPRN/MS-DFSNM coercion calls; outbound SMB to an attacker host |
| `T1003.006` DCSync | Credential Access | `DRSUAPI`/`DRSGetNCChanges` from a non-DC |
| `T1040` Network Sniffing | Credential Access / Discovery | Cleartext credentials present; promiscuous-mode side effects; ARP poisoning |
| `T1046` Network Service Discovery | Discovery (TA0007) | Port fan-out, failed-connection ratio, flag-based scans |
| `T1018` Remote System Discovery | Discovery | Host fan-out on one port; reverse DNS sweeps; broadcast discovery |
| `T1135` Network Share Discovery | Discovery | `srvsvc` share enumeration over SMB |
| `T1087.002` / `T1069.002` / `T1482` / `T1615` Account, Group, Trust, GPO Discovery | Discovery | Broad LDAP queries, recursive group expansion |
| `T1021` Remote Services (`.001` RDP, `.002` SMB, `.003` DCOM, `.004` SSH, `.005` VNC, `.006` WinRM) | Lateral Movement (TA0008) | Novel graph edges on admin protocols; movement chains |
| `T1210` Exploitation of Remote Services | Lateral Movement | Exploit strings on internal flows; crash/restart of target service |
| `T1570` Lateral Tool Transfer | Lateral Movement | Executables moving host-to-host over SMB/HTTP |
| `T1005` / `T1039` / `T1213` / `T1602` Data from Local System / Shared Drive / Repositories / Config Repository | Collection (TA0009) | Mass reads over SMB, NFS, HTTP; SNMP MIB dumps; config pulls |
| `T1074.001/.002` Data Staged | Collection | Internal volume convergence on one host |
| `T1560` Archive Collected Data | Collection | High-entropy archive artefacts in transit |
| `T1119` Automated Collection | Collection | Regular, identically-shaped collection flows |
| `T1071` Application Layer Protocol (`.001`–`.005`) | Command and Control (TA0011) | Beaconing, protocol/port mismatch, non-browser HTTP shape |
| `T1573.001/.002` Encrypted Channel | C2 | Custom crypto; anomalous TLS fingerprints and certificates |
| `T1572` Protocol Tunneling | C2 | Inner protocol inside an outer one; entropy and size anomalies |
| `T1090` Proxy (`.001`–`.004`) | C2 | Relay behaviour, RTT anomalies, SNI/Host mismatch |
| `T1571` Non-Standard Port | C2 | Protocol/port mismatch |
| `T1095` Non-Application Layer Protocol | C2 | ICMP/raw-socket channels |
| `T1102` Web Service (`.001`–`.003`) | C2 | Polling of paste/code/messaging platforms |
| `T1008` Fallback Channels | C2 | Secondary channel activating on primary failure |
| `T1104` Multi-Stage Channels | C2 | Destination or cadence change after initial contact |
| `T1105` Ingress Tool Transfer | C2 | Executable download after initial access |
| `T1132` Data Encoding / `T1001` Data Obfuscation | C2 | Base64/hex/custom encoding; junk padding; steganography |
| `T1219` Remote Access Tools (`.001` IDE Tunneling, `.002` Remote Desktop Software, `.003` Remote Access Hardware) | C2 | RMM vendor endpoints; long-lived interactive sessions |
| `T1205` Traffic Signaling (`.001` Port Knocking, `.002` Socket Filters) | Stealth / Persistence / C2 | Ordered failed-port sequence preceding a successful connection |
| `T1568` Dynamic Resolution (`.001`–`.003`) | C2 | NXDOMAIN bursts, low TTLs, DGA-shaped names |
| `T1041` Exfiltration Over C2 Channel | Exfiltration (TA0010) | Outbound-skewed volume inside the C2 flow |
| `T1048` Exfiltration Over Alternative Protocol (`.001`–`.003`) | Exfiltration | Bulk egress over DNS, FTP, SMTP, ICMP |
| `T1567` Exfiltration Over Web Service (`.001`–`.004`) | Exfiltration | Uploads to repos, cloud storage, paste sites, webhooks |
| `T1020` / `T1029` / `T1030` Automated / Scheduled / Size-Limited Transfer | Exfiltration | Regularity, scheduling, uniform chunking |
| `T1498` Network DoS (`.001` Direct Flood, `.002` Reflection Amplification) | Impact (TA0040) | Volumetric fan-in; amplification ratios |
| `T1499` Endpoint DoS (`.001`–`.004`) | Impact | Half-open accumulation, connection exhaustion, expensive-request floods, malformed input |
| `T1486` / `T1485` / `T1490` Data Encrypted for Impact / Destruction / Inhibit Recovery | Impact | Mass high-entropy SMB writes; mass deletes; backup-share attacks |
| `T1036` Masquerading | Stealth (TA0005) | Fingerprint/identity mismatches at every layer |
| `T1027` Obfuscated Files or Information | Stealth | Encoded/packed content in transit |
| `T1689` Downgrade Attack | Defense Impairment (TA0112) | Forced TLS/SMB/NTLM version reduction |
| `T1600` Weaken Encryption | Defense Impairment | Weak cipher negotiation, key-strength reduction |
| `T1599` Network Boundary Bridging (`.001` NAT Traversal) | Defense Impairment | Zone-crossing flows, dual-homed hosts, VLAN hopping |
| `T1553.004` Install Root Certificate | Defense Impairment | New CA in observed certificate chains |
| `T1556` Modify Authentication Process | Defense Impairment | Authentication behaviour inconsistent with policy |
| `T1207` Rogue Domain Controller | Defense Impairment | Unexpected replication traffic |
| `T1686` Disable or Modify System Firewall | Defense Impairment | Previously-blocked flows suddenly succeeding |
| `T1685` Disable or Modify Tools | Defense Impairment | Loss of expected agent/telemetry traffic from a host that is otherwise still active |

### 8.2 ATT&CK for ICS (v19.2)

| Technique | Tactic | Primary network observables |
|---|---|---|
| `T0819` Exploit Public-Facing Application / `T0883` Internet Accessible Device | Initial Access | OT protocol flows to or from internet space |
| `T0822` External Remote Services / `T0886` Remote Services | Initial Access / Lateral Movement | Vendor or IT-originated sessions into the OT zone |
| `T0848` Rogue Master | Initial Access | Control-class functions from a source that is not the designated master |
| `T0864` Transient Cyber Asset | Initial Access | New MAC/host appearing on the process network |
| `T0866` Exploitation of Remote Services | Initial Access / Lateral Movement | Malformed or exploit-shaped frames toward OT services |
| `T0858` Change Operating Mode | Execution / Evasion | RUN→STOP/PROGRAM commands |
| `T0871` Execution through API | Execution | OPC UA `Call` on methods; API-level control invocation |
| `T0821` Modify Controller Tasking | Execution | Task/cycle configuration writes |
| `T1694` Insecure Credentials (`.001` Default, `.002` Hardcoded) | Persistence / Lateral Movement | Authentication with vendor-default credentials |
| `T0873` Project File Infection | Persistence | Engineering project file transfer |
| `T0889` Modify Program / `T1693` Modify Firmware | Persistence / Inhibit Response / Impair Process Control | Logic or firmware image transfer |
| `T0859` Valid Accounts | Persistence / Lateral Movement | Legitimate OT credentials used from an anomalous source |
| `T1692` Unauthorized Message (`.001` Command Message, `.002` Reporting Message) | Evasion / Impair Process Control | Unauthorised control commands; falsified telemetry to the HMI |
| `T0872` Indicator Removal on Host / `T0849` Masquerading | Evasion | Log-clearing traffic; a host impersonating the HMI's identity |
| `T0840` Network Connection Enumeration | Discovery | Connection-table enumeration on OT devices |
| `T0842` Network Sniffing | Discovery | Cleartext OT protocols make passive capture trivial |
| `T0846` Remote System Discovery (`.001` Port Scan, `.002` Broadcast Discovery, `.003` Multicast Discovery) | Discovery | Unit-ID sweeps, `Who-Is`, `List Identity`, DCP `Identify All` |
| `T0888` Remote System Information Discovery | Discovery | Read Device Identification, Read SZL, device-info queries |
| `T0843` Program Download (`.001` Download All, `.002` Online Edit, `.003` Program Append) | Lateral Movement | Logic pushed to a controller |
| `T0867` Lateral Tool Transfer | Lateral Movement | Tooling moved between OT hosts |
| `T0830` Adversary-in-the-Middle | Collection | ARP/GOOSE/L2 manipulation inside the process network |
| `T0845` Program Upload | Collection | Logic read out of a controller |
| `T0861` Point & Tag Identification | Collection | Full address-space browse; tag enumeration |
| `T0801` Monitor Process State / `T0802` Automated Collection / `T0811` Data from Information Repositories | Collection | Sustained historian/OPC reads from a new source |
| `T0868` Detect Operating Mode | Collection | Mode-status polling |
| `T0885` Commonly Used Port / `T0869` Standard Application Layer Protocol / `T0884` Connection Proxy | Command and Control | C2 riding allowed OT ports and protocols; relays into the process network |
| `T0814` Denial of Service / `T0816` Device Restart/Shutdown | Inhibit Response Function | Malformed frames, restart commands, protocol floods |
| `T1691` Block Operational Technology Message / `T1695` Block Communications | Inhibit Response Function | Missing expected cyclic messages; suppressed unsolicited responses |
| `T0878` Alarm Suppression / `T0838` Modify Alarm Settings | Inhibit Response Function | Alarm-configuration writes; DNP3 "Disable Unsolicited" |
| `T0881` Service Stop / `T0809` Data Destruction | Inhibit Response Function | Service termination; historian/config destruction |
| `T0800` Activate Firmware Update Mode | Inhibit Response Function | Device placed into update mode outside a change window |
| `T0806` Brute Force I/O / `T0835` Manipulate I/O Image / `T0836` Modify Parameter | Impair Process Control | Rapid repeated writes; register/coil/setpoint modification |
| `T0813` Denial of Control / `T0815` Denial of View / `T0831` Manipulation of Control / `T0832` Manipulation of View | Impact | Loss or falsification of operator control and visibility |
| `T0882` Theft of Operational Information | Impact | Bulk process-data egress |

### 8.3 MITRE ATLAS (v5.6.0)

| Technique | Tactic | Primary network observables |
|---|---|---|
| `AML.T0006` Active Scanning | Reconnaissance (AML.TA0002) | Scanning of AI endpoints and model-serving paths |
| `AML.T0064` Gather RAG-Indexed Targets | Reconnaissance | Probing to map what a RAG system has indexed |
| `AML.T0002` Acquire Public AI Artifacts (`.000` Datasets, `.001` Models) | Resource Development (AML.TA0003) | Model/dataset downloads from public hubs |
| `AML.T0019` Publish Poisoned Datasets / `AML.T0058` Publish Poisoned Models / `AML.T0066` Retrieval Content Crafting | Resource Development | Source side of poisoned artefact and content fetches |
| `AML.T0010` AI Supply Chain Compromise (`.000` Hardware, `.001` AI Software, `.002` Data, `.003` Model) | Initial Access (AML.TA0004) | Artefact and dependency pulls from unvetted hosts |
| `AML.T0049` Exploit Public-Facing Application | Initial Access | Exploitation of model-serving or MLOps interfaces |
| `AML.T0012` Valid Accounts | Initial Access / Privilege Escalation | API keys and tokens in use from anomalous sources |
| `AML.T0040` AI Model Inference API Access | AI Model Access (AML.TA0000) | Inference API traffic — volume, source, and pattern |
| `AML.T0047` AI-Enabled Product or Service / `AML.T0044` Full AI Model Access | AI Model Access | Direct reachability of model artefacts or serving endpoints |
| `AML.T0051` LLM Prompt Injection (`.000` Direct, `.001` Indirect) | Execution (AML.TA0005) | Injection strings in request payloads or in retrieved content |
| `AML.T0053` AI Agent Tool Invocation | Execution / Privilege Escalation | Agent tool calls to unexpected destinations |
| `AML.T0011.000` User Execution: Unsafe AI Artifacts | Execution | Pickle-format model artefacts in transit |
| `AML.T0020` Poison Training Data / `AML.T0018` Manipulate AI Model / `AML.T0070` RAG Poisoning | Persistence (AML.TA0006) | Unauthorised writes to training stores and vector databases |
| `AML.T0061` LLM Prompt Self-Replication | Persistence | Self-propagating instruction content across systems |
| `AML.T0054` LLM Jailbreak | Privilege Escalation / Defense Evasion | Jailbreak scaffolds in payloads |
| `AML.T0068` LLM Prompt Obfuscation / `AML.T0067` LLM Trusted Output Components Manipulation | Defense Evasion (AML.TA0007) | Encoded, unicode-obfuscated, or output-spoofing content |
| `AML.T0015` Evade AI Model | Initial Access / Defense Evasion / Impact | Adversarially perturbed inputs to AI-based controls |
| `AML.T0055` Unsecured Credentials | Credential Access (AML.TA0013) | AI service keys in cleartext |
| `AML.T0007` Discover AI Artifacts / `AML.T0013` Discover AI Model Ontology / `AML.T0014` Discover AI Model Family / `AML.T0069` Discover LLM System Information | Discovery (AML.TA0008) | Enumeration of models, endpoints, and system instructions |
| `AML.T0035` AI Artifact Collection / `AML.T0036` Data from Information Repositories / `AML.T0037` Data from Local System | Collection (AML.TA0009) | Bulk artefact and dataset movement |
| `AML.T0043` Craft Adversarial Data (`.000`–`.004`) / `AML.T0042` Verify Attack / `AML.T0005` Create Proxy AI Model | AI Attack Staging (AML.TA0001) | Iterative query/response probing loops |
| `AML.T0072` Reverse Shell | Command and Control (AML.TA0014) | Outbound shell from AI infrastructure |
| `AML.T0024` Exfiltration via AI Inference API (`.000` Membership Inference, `.001` Model Inversion, `.002` Model Extraction) | Exfiltration (AML.TA0010) | Systematic high-volume querying |
| `AML.T0025` Exfiltration via Cyber Means | Exfiltration | Conventional egress of AI artefacts |
| `AML.T0056` Extract LLM System Prompt / `AML.T0057` LLM Data Leakage | Exfiltration | System instructions or sensitive data in responses |
| `AML.T0029` Denial of AI Service / `AML.T0034` Cost Harvesting / `AML.T0046` Spamming AI System with Chaff Data | Impact (AML.TA0011) | Sustained expensive or junk inference load |
| `AML.T0031` Erode AI Model Integrity / `AML.T0059` Erode Dataset Integrity | Impact | Feedback-loop and corpus poisoning volume |
| `AML.T0048.004` AI Intellectual Property Theft | Impact | Outcome of extraction or artefact exfiltration |
---

## 9. Part D — Triage, scoring, and correlation

### 9.1 Indicator weighting

Weights are starting values; recalibrate against your own false-positive rates.

| Weight | Indicator class | Rationale |
|---|---|---|
| **Very high (9–10)** | Threat-intel match on IP/domain/JA3/cert; ICS control-write from a rogue master; DCSync from a non-DC; confirmed exploit followed by outbound connection; OT device egressing to the internet; mass high-entropy SMB writes | Low false-positive rate, high consequence |
| **High (7–8)** | Beaconing to an unlisted destination with matching fingerprint; protocol/port mismatch; Kerberoasting signature; NTLM relay pattern; zone-edge violation; outbound-skewed heavy flow to a young ASN; executable transferred host-to-host | Specific, hard to produce benignly |
| **Medium (4–6)** | Non-standard port alone; long-lived flow alone; new external destination; off-hours access; scanning behaviour; encrypted-archive transfer; unusual TLS fingerprint | Requires corroboration |
| **Low (1–3)** | Short-lived flows; volume above average; TTL variance; single failed authentication; legacy protocol presence | Ubiquitous benignly; useful only in aggregate |

### 9.2 Correlation patterns that convert weak indicators into findings

Chains matter more than counts. Look explicitly for these composites:

| Composite | Reading |
|---|---|
| New destination **+** periodic **+** uniform sizes **+** off-hours persistence | C2 beacon (`T1071` + `T1573`) |
| Beacon **+** sudden large inbound response **+** new outbound connection to a different host | Tasking received, then lateral movement (`T1104` → `T1021`) |
| Auth success **+** share enumeration **+** admin-share write **+** service-control pipe | PsExec-style remote execution (`T1078` → `T1135` → `T1021.002` → `T1569.002`) |
| Scan **+** exploit string **+** service restart **+** new listener | Exploitation and foothold (`T1046` → `T1190`/`T1210` → `T1505`) |
| Mass internal reads **+** internal volume convergence **+** high-entropy archive **+** outbound-skewed transfer to a new ASN | Collection → staging → archiving → exfiltration (`T1039` → `T1074` → `T1560` → `T1041`/`T1048`) |
| Cleartext credentials observed **+** the same credential authenticating from a new source | Sniffed credential reused (`T1040` → `T1078`) |
| Rogue LLMNR/NBT-NS responses **+** inbound NTLM auth **+** onward SMB to a third host | Poisoning → relay → lateral movement (`T1557.001` → `T1550.002`) |
| IT-zone host **+** first-ever OT protocol flow **+** write function code **+** outside change window | OT intrusion (`T0886` → `T1692.001` → `T0836`) |
| Systematic inference queries **+** sustained volume **+** artefact egress | Model extraction then exfiltration (`AML.T0024.002` → `AML.T0025`) |
| Retrieved web content containing instructions **+** agent tool calls to a new destination **+** data in the request | Indirect prompt injection driving exfiltration (`AML.T0051.001` → `AML.T0053` → `AML.T0057`) |

### 9.3 Common analytic errors

| Error | Consequence | Correction |
|---|---|---|
| Reporting "no suspicious activity" without stating capture limits | Overstates assurance; the capture may simply not contain the evidence | Always report negative findings bounded by Stage 0 limits |
| Treating one indicator as a detection | High false-positive rate, analyst fatigue | Require corroboration across levels before escalating |
| Using absolute thresholds without baselining | Thresholds tuned for one environment fail in another; OT and IT invert several of them | Express thresholds relative to peer group and protocol norm |
| Trusting the port to identify the protocol | Misses every tunnel and every relocated service | Classify by payload, then compare to the port |
| Ignoring encrypted traffic because payload is unavailable | Discards most of the estate | Metadata analysis — fingerprints, sizes, timing, certificates — survives encryption |
| Analysing beacons by interval variance alone | Misses jittered implants; drowns in benign beacons | Use the four-signal method (interval, spectral, size, duty cycle) plus a destination allow-list |
| Applying IT assumptions to OT | Long-lived periodic flows are normal in OT; short-lived novel ones are the anomaly | Invert the heuristics inside the process network |
| Mapping to techniques with unstated confidence | Findings read as fact and propagate | Record each mapping as a hypothesis with a confidence level and the evidence supporting it |
| Using stale framework versions | Mappings cite revoked ICS techniques or the pre-split Defense Evasion tactic | Pin the framework version in the report header |

---
