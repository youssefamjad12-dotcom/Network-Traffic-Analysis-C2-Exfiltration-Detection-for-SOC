# Evidence — Commands and display filters used

Tool versions: TShark 4.2.2 (Git v4.2.2), capinfos, tcpdump. Zeek and Suricata were **not** installed. All work was done on the original PCAPs, read-only.

## Inventory

```bash
capinfos -c -u -a -e -M webshell.pcap nmap.pcap C2+DGA-ether.pcap
sha256sum webshell.pcap nmap.pcap C2+DGA-ether.pcap
tshark -r <pcap> -q -z io,phs
tshark -r <pcap> -q -z endpoints,ip
tshark -r <pcap> -q -z conv,tcp
```

## webshell.pcap

```bash
tshark -r webshell.pcap -Y 'http.request' -T fields \
  -e frame.number -e frame.time_relative -e tcp.stream -e http.request.method \
  -e http.request.uri -e http.user_agent -e http.host -e http.content_length

tshark -r webshell.pcap -Y 'http.response' -T fields \
  -e frame.number -e tcp.stream -e http.response.code -e http.content_type \
  -e http.content_length -e http.server

tshark -r webshell.pcap -q -z follow,tcp,ascii,1          # upload POST + page
tshark -r webshell.pcap -Y 'frame.number==17' -V | grep -i csrf
tshark -r webshell.pcap -Y 'http.cookie || http.set_cookie' -T fields \
  -e frame.number -e http.cookie -e http.set_cookie
tshark -r webshell.pcap -Y 'tcp.stream==<n> && http.response' -T fields -e http.file_data
tshark -r webshell.pcap -T fields -e eth.src -e eth.dst -e ip.src
```

Shell extraction (Python, one-off): hex-decode `http.file_data` of frame 27 → split at `filename="shell.php"` + `\r\n\r\n` → trim trailing `\r\n--<boundary>` → 135 bytes.

## nmap.pcap

```bash
tshark -r nmap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src -e ip.dst \
  | sort | uniq -c | sort -rn
tshark -r nmap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.dstport \
  | sort -u | wc -l                                        # 65535
tshark -r nmap.pcap -Y 'tcp' -T fields -e tcp.flags.str | sort | uniq -c | sort -rn
tshark -r nmap.pcap -Y 'ip.src==172.16.173.138 && tcp.flags.syn==1 && tcp.flags.ack==1' \
  -T fields -e tcp.srcport | sort -n | uniq -c
tshark -r nmap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==172.16.173.1' \
  -T fields -e ip.ttl | sort -n | uniq -c                  # 24 distinct TTLs 37..64
tshark -r nmap.pcap -Y 'http.request' -T fields -e http.request.method -e http.request.uri \
  -e http.user_agent | sort | uniq -c | sort -rn
tshark -r nmap.pcap -Y 'arp' -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u
tshark -r nmap.pcap -Y 'tcp.len==4 && ip.src==172.16.173.1' -T fields -e tcp.dstport -e tcp.payload
tshark -r nmap.pcap -Y 'tls.handshake.type==1' -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

## C2+DGA-ether.pcap

```bash
tshark -r 'C2+DGA-ether.pcap' -Y 'dns.flags.response==0' -T fields -e ip.src -e dns.qry.name \
  | sort | uniq -c | sort -rn
tshark -r 'C2+DGA-ether.pcap' -Y 'dns.flags.response==0 && ip.src==192.168.1.120' -T fields \
  -e frame.time_relative -e dns.qry.name -e dns.qry.type -e ip.dst
tshark -r 'C2+DGA-ether.pcap' -Y 'dns.flags.response==1 && ip.dst==192.168.1.120' -T fields \
  -e dns.qry.name -e dns.flags.rcode | sort | uniq -c
tshark -r 'C2+DGA-ether.pcap' -Y 'dns.qry.name contains "dga-lab" && ip.src==192.168.1.13' -T fields \
  -e frame.time_relative -e dns.flags.response -e dns.flags.rcode -e dns.qry.type
tshark -r 'C2+DGA-ether.pcap' -Y 'dns.qry.name contains "queniuck" && ip.src==192.168.1.13' -T fields \
  -e frame.time_relative -e dns.qry.type
tshark -r 'C2+DGA-ether.pcap' -Y 'tcp.port==4444 && tcp.flags.syn==1 && tcp.flags.ack==0' -T fields \
  -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
tshark -r 'C2+DGA-ether.pcap' -Y 'tls.handshake.type==1' -T fields \
  -e ip.dst -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn
tshark -r 'C2+DGA-ether.pcap' -Y 'arp' -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u
```

Stream reassembly for the 4444 payloads (Python + TShark fields, de-duplicated by `tcp.seq_raw`):

```bash
tshark -r 'C2+DGA-ether.pcap' -Y 'tcp.stream==3619 && ip.src==192.168.1.13 && tcp.len>0' \
  -T fields -e tcp.seq_raw -e tcp.payload
```

Framing: `uint32le length` + body (0x0003E6BC = 255,676). Artifacts written to `Evidence/Samples/`.

```bash
file payload_a.exe
objdump -p payload_a.exe | head -60          # PE32+ DLL, export name "server.dll"
objdump -h payload_a.exe                     # .text .rdata .data .pdata _RDATA .reloc
strings -el -n 6 payload_a.exe | head -40    # SeDebugPrivilege, crypto providers, named pipes
cmp -l payload_a.exe payload_b.exe | wc -l   # 180 differing bytes (tail only)
```

## Notes on interpretation

- Reverse-DNS traffic to `192.168.1.1` (331 queries) is DHCP/DNS housekeeping.
- DNS packets duplicating between `127.0.0.1` and `192.168.1.13` are local-resolver copies of the same queries; counts were de-duplicated by host.
- `icmp && dns` frames are ICMP *destination-unreachable* messages quoting a DNS packet — not a DNS-over-ICMP tunnel.
- ICMP echo to 192.168.1.120 carries a zero-length payload (4 requests, 2 replies) — a liveness check, not exfiltration.
