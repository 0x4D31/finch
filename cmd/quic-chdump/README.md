quic-chdump
===========

`quic-chdump` is a small command‑line tool that uses `pkg/quic` to extract QUIC ClientHello messages from PCAP files or live network capture. It logs the SNI and JA3/JA4 fingerprints for each ClientHello.

## Installation

```bash
go install -tags pcap ./cmd/quic-chdump
```

On Linux and macOS you must have the libpcap development headers installed.

## Usage


```
Usage: quic-chdump [--read READ] [--iface IFACE] [--filter FILTER] [--hex] [--output OUTPUT] [--print]

Options:
  --read READ, -r READ   read packets from pcap file
  --iface IFACE, -i IFACE
                         interface for live capture
  --filter FILTER, -f FILTER
                         BPF filter expression for QUIC traffic [default: udp and port 443]
  --hex, -x              include hex dump of ClientHello in JSON output; with -p, also prints hex after each connection
  --output OUTPUT, -o OUTPUT
                         path to JSONL log file [default: quic-chdump.jsonl]
  --print, -p            print aggregated output to stdout (suppresses duplicates)
  --help, -h             display this help and exit
```

### Example

Capture QUIC traffic on interface en0, print results to stdout and include hex dumps:

```
quic-chdump -i en0 -f "udp and port 443" -p -x

10.40.23.21  -> 104.16.123.96  [JA3: 0aad1822ea146803a88cbd55ad13f042]  [JA4: q13d0312h3_55b375c5d22e_5a06198afb93]  SNI: www.cloudflare.com

  ╭──────────────────────────── ClientHello Hex Dump ──────────────────────────╮
  00000000  16 03 01 07 d7 01 00 07  d3 03 03 22 37 58 26 94  |..........."7X&.|
  00000010  cf 17 e3 92 93 d5 79 de  a2 4c b8 41 0d ee 15 5b  |......y..L.A...[|
  00000020  7a df ee 0b 0c d0 12 84  1f b6 d5 00 00 06 13 01  |z...............|
  00000030  13 02 13 03 01 00 07 a4  00 2d 00 02 01 01 44 cd  |.........-....D.|
  00000040  00 05 00 03 02 68 33 00  0a 00 0a 00 08 11 ec 00  |.....h3.........|
  00000050  1d 00 17 00 18 00 2b 00  03 02 03 04 00 0d 00 14  |......+.........|
  00000060  00 12 04 03 08 04 04 01  05 03 08 05 05 01 08 06  |................|
  00000070  06 01 02 01 00 33 04 ea  04 e8 11 ec 04 c0 a7 23  |.....3.........#|
  00000080  05 a8 45 99 4c 84 41 fc  9b bf 43 75 58 60 78 45  |..E.L.A...CuX`xE|
  00000090  73 5b 1a 1d d7 a5 dc 2b  63 e0 35 4c 38 d3 15 57  |s[.....+c.5L8..W|
...
```

quic-chdump writes JSONL logs to the specified output file and optionally prints aggregated summaries. Hex dumps allow you to inspect the exact TLS handshake contents.