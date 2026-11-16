<div align="center">

# 🛡️ Network Traffic Analysis & C2/Exfiltration Detection for SOC

**Digital Egypt Pioneers Initiative (DEPI) — Graduation Capstone, Project 1**

![Focus](https://img.shields.io/badge/focus-Network%20Forensics%20%7C%20SOC-blue)
![Tools](https://img.shields.io/badge/tools-Wireshark%20%7C%20TShark%20%7C%20Suricata%20%7C%20Ollama-orange)
![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)
![Status](https://img.shields.io/badge/status-4%20weeks%20complete-brightgreen)

</div>

---

## 📖 Overview

This project simulates the work of a SOC analyst investigating suspicious network activity. Starting from packet captures of a lab network, it covers baselining normal traffic, detecting reconnaissance, command-and-control (C2) and web-shell activity, mapping findings to **MITRE ATT&CK**, using a local LLM to assist triage, and delivering a final SOC-style investigation report.

Every finding is backed by packet evidence and labelled with a confidence level: **Confirmed / Likely / Possible**.

**Lab:** VMware network `192.168.1.0/24`: gateway, Ubuntu server, Windows 11 client, Kali attacker and a Wazuh server.

---

## 🗓️ Project Plan & Deliverables

| Week | Focus | Deliverables | Location |
|:---:|---|---|---|
| **1** | Network foundations & traffic capture | Network protocol map · Wireshark filter cheat sheet · Annotated PCAP · Baseline traffic summary | [`week-1/`](week-1) |
| **2** | Protocol analysis & anomaly identification | Protocol analysis report · Suspicious traffic findings · Suricata alert review · IOC list · PCAP evidence | [`week-2&3/`](week-2%263) |
| **3** | Recon, C2 & exfiltration detection | Scan detection report · C2/exfiltration analysis · MITRE ATT&CK mapping · Detection logic | [`week-2&3/`](week-2%263) |
| **4** | AI-assisted triage & reporting | Final threat detection report · Human-validated findings · Executive summary · Remediation & detection recommendations | [`week 4/`](week%204) |

---

## 📂 Repository Structure

```
SOC-DFIR-Automation-Capstone/
├── week-1/
│   ├── Network_Map.pdf                  # Protocol / topology map
│   ├── Wireshark_Cheat_Sheet.pdf        # Filters, statistics, TShark commands
│   ├── Annotated_PCAP.pdf               # Key frames and takeaways
│   ├── Baseline_Traffic_Summary.pdf     # What "normal" looks like
│   └── pcaps/                           # 4 baseline captures
├── week-2&3/
│   ├── index.html                       # Interactive SOC report (open in browser)
│   └── pcaps/                           # webshell.pcap · nmap.pcap · C2+DGA-ether.pcap
└── week 4/
    ├── Investigation-Report.md / .pdf / .docx / .html
    ├── IOCs.csv                         # Machine-readable indicators
    ├── Timeline.csv                     # Merged event timeline (UTC)
    └── Evidence/
        ├── commands-and-filters.md      # Every command and filter used
        ├── webshell-command-transcript.md
        └── Samples/                     # Extracted artifacts + SHA256SUMS.txt
```

---

## 🔬 Week 1: Network Foundations & Traffic Capture

Reviewed OSI/TCP-IP, addressing and common protocols (HTTP, DNS, SMTP, SMB, SSH, RDP), then captured browsing, DNS, TCP handshake and file-transfer traffic.

- 4 captures · ~6,069 frames · ~1.78 MB
- Baseline of normal DNS, NTP and SMB behaviour to compare future captures against

## 🔍 Weeks 2–3: Protocol Analysis, Recon, C2 & Exfiltration Detection

Manual **Wireshark** investigation combined with **Suricata** IDS review (130 alerts across 3 malicious captures). The interactive report includes:

- Suricata alert analysis with packet-checked verdicts (true vs false positives)
- MITRE ATT&CK map
- Wireshark vs Suricata comparison
- AI investigation summary
- IOC repository and attack timelines

> 💡 Download `week-2&3/index.html` and open it in a browser.

## 📝 Week 4: AI-Assisted Triage & Final Report

A local LLM (Ollama) was used to help summarise findings and draft write-ups; **all AI output was validated manually against packet evidence** before inclusion. The final report contains the executive summary, findings with packet evidence, ATT&CK mapping, IOCs, detections and limitations.

---

## 🎯 Key Findings

| Case | Capture | Finding | Verdict |
|---|---|---|---|
| 1 | `webshell.pcap` | Unrestricted file upload → web shell → 15 discovery commands as `www-data` on `wazuh-server` | 🔴 Critical · Confirmed |
| 2 | `nmap.pcap` | All 65,535 ports scanned in ~1 s, then service detection and NSE web probes with randomised TTL/IP-ID | 🟠 Medium · Confirmed |
| 3 | `C2+DGA-ether.pcap` | 255,676-byte packed PE DLL delivered over TCP/4444, then 4 DGA domains in 5.2 s | 🔴 Critical · Confirmed delivery, Likely C2 |

**Correlation:** the scanned host (`172.16.173.138`) and the web-shell victim (`192.168.1.128`) are two NICs of the same server, so reconnaissance (07 Nov 19:41 UTC) and exploitation (08 Nov 09:29 UTC) form one kill chain.

**Scope note:** no data exfiltration or lateral movement is visible in these three captures. Only these PCAPs were available (no host logs or memory).

### MITRE ATT&CK Coverage

| Tactic | Techniques |
|---|---|
| Reconnaissance | T1595.002 |
| Initial Access | T1190 |
| Persistence | T1505.003 |
| Discovery | T1046, T1033, T1082, T1016, T1057, T1083 |
| Privilege Escalation | T1548.001, T1548.003 |
| Command & Control | T1105, T1571, T1568.002, T1071.004, T1008 |
| Defense Evasion | T1027 |

---

## 🛠️ Tools

| Category | Tools |
|---|---|
| Packet analysis | Wireshark, TShark 4.2.2, `capinfos` |
| IDS | Suricata |
| AI assistance | Ollama (local LLM) |
| Framework | MITRE ATT&CK |
| Lab | VMware, Kali Linux, Ubuntu Server, Windows 11, Wazuh |
| Reporting | Markdown, HTML, PDF, DOCX, CSV |

---

## ▶️ Reproduce the Analysis

```bash
git clone https://github.com/Mohamedgomaa254/SOC-DFIR-Automation-Capstone.git
cd SOC-DFIR-Automation-Capstone

# Web-shell requests
tshark -r "week-2&3/pcaps/webshell.pcap" -Y 'http.request' \
       -T fields -e http.request.method -e http.request.uri

# Distinct ports probed by Nmap
tshark -r "week-2&3/pcaps/nmap.pcap" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
       -T fields -e tcp.dstport | sort -u | wc -l

# DGA lookups from the infected host
tshark -r "week-2&3/pcaps/C2+DGA-ether.pcap" \
       -Y 'dns.flags.response==0 && ip.src==192.168.1.120' \
       -T fields -e frame.time_relative -e dns.qry.name -e dns.qry.type
```

**Start here:** [`week 4/Investigation-Report.md`](week%204/Investigation-Report.md) · full command list in `week 4/Evidence/commands-and-filters.md`.

---

## ⚠️ Safety Notice

- `week 4/Evidence/Samples/*.dll.bin` are **extracted malware bytes**, stored non-executable. **Never run or load them** outside an isolated sandbox.
- The `.pcap` files are **untrusted input**. Analyse them inside a VM.
- All activity took place in a **private lab for educational purposes**.

---

## 👤 Author

**Youssef Amjad**
🔗 [GitHub](https://github.com/youssefamjad12-dotcom)

<sub>Graduation project · Digital Egypt Pioneers Initiative</sub>
