# Week 4 — Attack Investigation Output

Deliverables from analysing the three Week 2–3 captures:

- `webshell.pcap` — web-shell upload and post-exploitation
- `nmap.pcap` — full-port reconnaissance
- `C2+DGA-ether.pcap` — C2 payload delivery and DGA

## Read first

**`Investigation-Report.md`** — the full report (executive summary, findings with packet evidence, ATT&CK mapping, IOCs, detections, limitations). Also exported as `Investigation-Report.pdf` and `Investigation-Report.docx`.

## Files

| File | Contents |
|---|---|
| `Investigation-Report.md` / `.html` / `.pdf` / `.docx` | Full investigation, three cases + correlation |
| `README.md` | This index |
| `IOCs.csv` | Machine-readable indicators (raw, undefanged) |
| `Timeline.csv` | Merged event timeline across the three captures (UTC) |
| `Evidence/commands-and-filters.md` | Every command, filter and reassembly step used |
| `Evidence/webshell-command-transcript.md` | The 15 web-shell commands and their verbatim outputs |
| `Evidence/Samples/shell.php` | Web shell recovered from the POST body (135 B) |
| `Evidence/Samples/payload_4444_stream3619.dll.bin` | Stage-2 DLL, build A (inert) |
| `Evidence/Samples/payload_4444_stream3621.dll.bin` | Stage-2 DLL, build B (inert) |
| `Evidence/Samples/SHA256SUMS.txt` | Hashes for captures and samples |

## Verdicts at a glance

| Case | Verdict | Confidence |
|---|---|---|
| Web shell on `192.168.1.128` (`wazuh-server`) via `/upload.php` | Full compromise as `www-data`, 15 discovery commands, SUID hunt | Confirmed |
| Full 65,535-port scan of `172.16.173.138` from `172.16.173.1` | Nmap SYN scan + service detection + NSE web probes, ~1 s sweep | Confirmed |
| `192.168.1.13` → `192.168.1.120` on TCP/4444 | 255,676-byte packed PE DLL (`server.dll`) delivered twice | Confirmed |
| `192.168.1.120` → 8.8.8.8 | 4 DGA domains in 5.2 s, all NXDOMAIN/NODATA | Confirmed |
| `c2.dga-lab.com` from `192.168.1.13` | Two failed C2 lookups 25.3 s apart | Confirmed |
| `102.132.97.54:443` | Long-lived TLS without SNI, 793 s — watchlist only | Possible |

The scanned host and the web-shell victim are the **same machine**: `172.16.173.138` (MAC `00:0c:29:52:c7:95`, NIC `ens36`) and `192.168.1.128` (MAC `00:0c:29:52:c7:8b`, NIC `ens33`) are the two interfaces of `wazuh-server`, with identical service sets (22/80/443/1514/1515/55000). Recon on 2026-11-07 19:41 UTC → exploitation on 2026-11-08 09:29 UTC.

## Handling warning

`Evidence/Samples/*.dll.bin` are **extracted malware bytes**, stored unexecutable. Do not run, load or copy them to a Windows host outside a sandbox. The capture files themselves are untrusted input.

## Reproduce

```bash
tshark -r webshell.pcap -Y 'http.request' -T fields -e http.request.method -e http.request.uri
tshark -r nmap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.dstport | sort -u | wc -l
tshark -r C2+DGA-ether.pcap -Y 'dns.flags.response==0 && ip.src==192.168.1.120' \
       -T fields -e frame.time_relative -e dns.qry.name -e dns.qry.type
```

Full command list with filters: `Evidence/commands-and-filters.md`.
