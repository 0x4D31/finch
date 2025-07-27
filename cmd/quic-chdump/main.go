//go:build pcap

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	fp "github.com/0x4D31/fingerproxy/pkg/fingerprint"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
	arg "github.com/alexflint/go-arg"
	"github.com/dreadl0ck/tlsx"

	"github.com/0x4D31/finch/pkg/quic"
)

type connKey struct {
	SrcIP, DstIP        string
	DstPort             layers.UDPPort
	SNI, JA3, JA4, ALPN string
}

type cliArgs struct {
	File    string `arg:"-r,--read" help:"read packets from pcap file"`
	Iface   string `arg:"-i,--iface" help:"interface for live capture"`
	Filter  string `arg:"-f,--filter" help:"BPF filter expression for QUIC traffic [default: udp and port 443]" default:"udp and port 443"`
	DumpHex bool   `arg:"-x,--hex" help:"include hex dump of ClientHello in JSON output; with -p, also prints hex after each connection"`
	Output  string `arg:"-o,--output" help:"path to JSONL log file [default: quic-chdump.jsonl]" default:"quic-chdump.jsonl"`
	Print   bool   `arg:"-p,--print" help:"print aggregated output to stdout (suppresses duplicates)"`
}

var (
	cli      cliArgs
	keyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	valStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	encoder *json.Encoder
	seen    map[connKey]struct{}
)

func main() {
	p, err := arg.NewParser(arg.Config{Program: "quic-chdump"}, &cli)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := p.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, arg.ErrHelp) {
			p.WriteHelp(os.Stdout)
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if (cli.File == "") == (cli.Iface == "") {
		fmt.Fprintln(os.Stderr, "exactly one of -r or -i required")
		os.Exit(1)
	}
	f, err := os.OpenFile(cli.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	encoder = json.NewEncoder(f)
	encoder.SetEscapeHTML(false)
	if cli.Print {
		seen = make(map[connKey]struct{})
	}
	expr := cli.Filter

	var (
		src       *gopacket.PacketSource
		closeFunc func()
	)

	if cli.File != "" {
		handle, err := pcap.OpenOffline(cli.File)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := handle.SetBPFFilter(expr); err != nil {
			handle.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		src = gopacket.NewPacketSource(handle, handle.LinkType())
		closeFunc = handle.Close
	} else {
		handle, err := pcap.OpenLive(cli.Iface, 65535, true, pcap.BlockForever)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := handle.SetBPFFilter(expr); err != nil {
			handle.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		src = gopacket.NewPacketSource(handle, handle.LinkType())
		closeFunc = handle.Close
	}
	defer closeFunc()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}
			processPacket(pkt)
		}
	}
}

func processPacket(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}
	var srcIP, dstIP net.IP
	switch nl := netLayer.(type) {
	case *layers.IPv4:
		srcIP, dstIP = nl.SrcIP, nl.DstIP
	case *layers.IPv6:
		srcIP, dstIP = nl.SrcIP, nl.DstIP
	default:
		return
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)
	rec, err := quic.ExtractClientHello(udp.Payload)
	if err != nil {
		return
	}
	md := &metadata.Metadata{ClientHelloRecord: rec, IsQUIC: true}
	ch := &tlsx.ClientHello{}
	if err := ch.Unmarshal(rec); err != nil {
		return
	}
	ja3, errJA3 := fp.JA3Fingerprint(md)
	if errJA3 != nil {
		fmt.Fprintln(os.Stderr, "JA3 fingerprint error:", errJA3)
		ja3 = ""
	}
	ja4, errJA4 := fp.JA4Fingerprint(md)
	if errJA4 != nil {
		fmt.Fprintln(os.Stderr, "JA4 fingerprint error:", errJA4)
		ja4 = ""
	}
	ts := packet.Metadata().Timestamp.Format("2006-01-02 15:04:05")

	var clientHelloHex string
	if cli.DumpHex {
		clientHelloHex = hex.EncodeToString(rec)
	}

	out := struct {
		Timestamp      string            `json:"timestamp"`
		SrcIP          string            `json:"srcIP"`
		SrcPort        layers.UDPPort    `json:"srcPort"`
		DstIP          string            `json:"dstIP"`
		DstPort        layers.UDPPort    `json:"dstPort"`
		JA3            string            `json:"ja3"`
		JA4            string            `json:"ja4"`
		ClientHello    *tlsx.ClientHello `json:"clientHello"`
		ClientHelloHex string            `json:"clientHelloHex,omitempty"`
	}{
		Timestamp:      ts,
		SrcIP:          srcIP.String(),
		SrcPort:        udp.SrcPort,
		DstIP:          dstIP.String(),
		DstPort:        udp.DstPort,
		JA3:            ja3,
		JA4:            ja4,
		ClientHello:    ch,
		ClientHelloHex: clientHelloHex,
	}
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encode error:", err)
	}

	if cli.Print {
		key := connKey{
			SrcIP:   srcIP.String(),
			DstIP:   dstIP.String(),
			DstPort: udp.DstPort,
			SNI:     ch.SNI,
			JA3:     ja3,
			JA4:     ja4,
			ALPN:    strings.Join(ch.ALPNs, ","),
		}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			src := fmt.Sprintf("%-12s", key.SrcIP)
			dst := fmt.Sprintf("%-12s", key.DstIP)
			line := fmt.Sprintf("%s %s %s  [%s %s]  [%s %s]  %s %s",
				src, "->", dst,
				keyStyle.Render("JA3:"), key.JA3,
				keyStyle.Render("JA4:"), key.JA4,
				keyStyle.Render("SNI:"), valStyle.Render(key.SNI))
			fmt.Println(line)
			if cli.DumpHex && clientHelloHex != "" {
				fmt.Println()
				fmt.Println(keyStyle.Render("  ╭──────────────────────────── ClientHello Hex Dump ──────────────────────────╮"))
				for _, line := range strings.Split(hex.Dump(rec), "\n") {
					if line != "" {
						fmt.Println(dimStyle.Render("  " + line))
					}
				}
				fmt.Println()
			}
		}
	}
}
