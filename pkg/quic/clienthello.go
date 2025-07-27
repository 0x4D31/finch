package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var (
	saltV1      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2      = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	ErrNoCrypto = errors.New("no crypto frame")
)

const (
	DefaultStateLimit = 1024
	DefaultStateTTL   = 30 * time.Second
)

// Option configures a Parser.
type Option func(*Parser)

// WithStateLimit limits how many connection states are kept in memory.
// Values <= 0 are ignored.
func WithStateLimit(l int) Option {
	return func(p *Parser) {
		if l > 0 {
			p.stateLimit = l
		}
	}
}

// WithStateTTL sets the eviction timeout for connection state.
// Durations <= 0 are ignored.
func WithStateTTL(ttl time.Duration) Option {
	return func(p *Parser) {
		if ttl > 0 {
			p.stateTTL = ttl
		}
	}
}

// Parser extracts ClientHello records from QUIC Initial packets.
type Parser struct {
	states     sync.Map
	stateCount atomic.Int64
	stateLimit int
	stateTTL   time.Duration
	ticker     *time.Ticker
	done       chan struct{}
	once       sync.Once
	wg         sync.WaitGroup
}

// NewParser returns a new Parser configured with opts.
func NewParser(opts ...Option) *Parser {
	p := &Parser{stateLimit: DefaultStateLimit, stateTTL: DefaultStateTTL}
	for _, o := range opts {
		o(p)
	}
	p.ticker = time.NewTicker(p.stateTTL)
	p.done = make(chan struct{})
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			select {
			case <-p.ticker.C:
				p.maybeGC()
			case <-p.done:
				p.ticker.Stop()
				return
			}
		}
	}()
	return p
}

var defaultParser = NewParser()

type connState struct {
	mu  sync.Mutex        // protects buf
	buf map[uint64][]byte // off -> data
	pn  uint64            // highest packet number seen
	ts  time.Time         // last activity
}

func (p *Parser) maybeGC() {
	if p.stateCount.Load() <= int64(p.stateLimit) {
		return
	}
	cutoff := time.Now().Add(-p.stateTTL)
	p.states.Range(func(k, v any) bool {
		st := v.(*connState)
		if st.ts.Before(cutoff) {
			p.states.Delete(k)
			p.stateCount.Add(-1)
		}
		return true
	})
}

// Close stops the parser's background goroutine.
func (p *Parser) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.done) })
	p.wg.Wait()
}

func hkdfExpandLabel(secret []byte, label string, l int) ([]byte, error) {
	b := make([]byte, 3, 3+6+len(label)+1)
	binary.BigEndian.PutUint16(b, uint16(l))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = append(b, 0)
	out := make([]byte, l)
	n, err := hkdf.Expand(sha256.New, secret, b).Read(out)
	if err != nil || n != l {
		return nil, fmt.Errorf("hkdf expand failed")
	}
	return out, nil
}

func deriveInitialKeys(dcid, salt []byte, version uint32, keyLen int) (key, iv, hp []byte, err error) {
	if keyLen != 16 && keyLen != 32 {
		keyLen = 16
	}
	initialSecret := hkdf.Extract(sha256.New, dcid, salt)
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", sha256.Size)
	if err != nil {
		return nil, nil, nil, err
	}

	keyLabel := "quic key"
	ivLabel := "quic iv"
	hpLabel := "quic hp"
	if version == 0x6b3343cf || version == 0x709a50c4 {
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
	}

	if key, err = hkdfExpandLabel(clientSecret, keyLabel, keyLen); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = hkdfExpandLabel(clientSecret, ivLabel, 12); err != nil {
		return nil, nil, nil, err
	}
	if hp, err = hkdfExpandLabel(clientSecret, hpLabel, keyLen); err != nil {
		return nil, nil, nil, err
	}
	return
}

func readVarInt(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	prefix := b[0] >> 6
	l := 1 << prefix
	if len(b) < l {
		return 0, 0, io.ErrUnexpectedEOF
	}
	var v uint64
	switch prefix {
	case 0:
		v = uint64(b[0] & 0x3f)
	case 1:
		v = uint64(b[0]&0x3f)<<8 | uint64(b[1])
	case 2:
		v = uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	case 3:
		v = uint64(b[0]&0x3f)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	}
	return v, l, nil
}

func decodePN(b []byte) uint64 {
	var pn uint64
	for _, x := range b {
		pn = pn<<8 | uint64(x)
	}
	return pn
}

func reconstructPN(trunc uint64, pnLen int, highest uint64) uint64 {
	expected := highest + 1
	pnWin := uint64(1) << (pnLen * 8)
	pnHWin := pnWin / 2
	pnMask := pnWin - 1
	candidate := (expected & ^pnMask) | trunc
	if candidate+pnHWin <= expected {
		candidate += pnWin
	} else if candidate > expected+pnHWin {
		candidate -= pnWin
	}
	return candidate
}

func decodePacketType(first byte, version uint32) (uint8, error) {
	switch version {
	case 0x00000001:
		return uint8((first >> 4) & 0x03), nil
	case 0x6b3343cf, 0x709a50c4:
		return uint8(first & 0x03), nil
	default:
		return 0, fmt.Errorf("unknown QUIC version 0x%08x", version)
	}
}

func computePNLen(first, mask0 byte, version uint32) int {
	pnLenFirst := first ^ (mask0 & 0x0f)
	switch version {
	case 0x6b3343cf, 0x709a50c4:
		return int((pnLenFirst>>2)&0x3) + 1
	default:
		return int(pnLenFirst&0x3) + 1
	}
}

func headerProtectionMask(hpKey, sample []byte, alg string) []byte {
	switch alg {
	case "aes":
		block, _ := aes.NewCipher(hpKey)
		mask := make([]byte, block.BlockSize())
		block.Encrypt(mask, sample)
		return mask[:5]
	case "chacha":
		// RFC 9001 §5.4.3 specifies a 5 byte mask for header protection.
		// The ChaCha20 construction therefore also returns a 5 byte mask
		// even though the key is 32 bytes.
		counter := binary.LittleEndian.Uint32(sample[:4])
		c, _ := chacha20.NewUnauthenticatedCipher(hpKey, sample[4:16])
		c.SetCounter(counter)
		mask := make([]byte, 5)
		c.XORKeyStream(mask, mask)
		return mask
	}
	return nil
}

func applyHeaderProtectionMask(first *byte, pn []byte, mask []byte) {
	if len(mask) == 0 {
		return
	}
	*first ^= mask[0] & 0x0f
	for i := range pn {
		pn[i] ^= mask[i+1]
	}
}

func applyHeaderProtection(first *byte, pn []byte, hpKey, sample []byte, alg string) {
	mask := headerProtectionMask(hpKey, sample, alg)
	applyHeaderProtectionMask(first, pn, mask)
}

func decryptInitial(key, iv []byte, pn uint64, header, payload []byte) ([]byte, error) {
	var aead cipher.AEAD
	var err error
	switch len(key) {
	case 16:
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
	case 32:
		aead, err = chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("invalid key length %d", len(key))
	}
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pnBytes, pn)
	for i := 0; i < len(nonce) && i < len(pnBytes); i++ {
		nonce[len(nonce)-1-i] ^= pnBytes[len(pnBytes)-1-i]
	}
	return aead.Open(nil, nonce, payload, header)
}

func (p *Parser) getState(dcid []byte) *connState {
	key := string(dcid)
	if v, ok := p.states.Load(key); ok {
		st := v.(*connState)
		st.ts = time.Now()
		return st
	}
	st := &connState{buf: make(map[uint64][]byte), ts: time.Now()}
	p.states.Store(key, st)
	p.stateCount.Add(1)
	p.maybeGC()
	return st
}

func (p *Parser) addCrypto(dcid []byte, off uint64, data []byte) ([]byte, bool) {
	st := p.getState(dcid)
	st.ts = time.Now()
	st.mu.Lock()
	if _, ok := st.buf[off]; !ok {
		st.buf[off] = data
	}

	hdr, ok := st.buf[0]
	if !ok || len(hdr) < 4 {
		st.mu.Unlock()
		return nil, false
	}
	l := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	target := 4 + l

	var out []byte
	var pos uint64
	for pos < uint64(target) {
		b, ok := st.buf[pos]
		if !ok {
			st.mu.Unlock()
			return nil, false
		}
		out = append(out, b...)
		pos += uint64(len(b))
	}
	st.mu.Unlock()
	if len(out) < target {
		return nil, false
	}
	p.states.Delete(string(dcid))
	p.stateCount.Add(-1)
	return out[:target], true
}

func (p *Parser) parseCryptoFrames(dcid []byte, data []byte) ([]byte, bool, error) {
	i := 0
	parsed := false
	for i < len(data) {
		t, n, err := readVarInt(data[i:])
		if err != nil {
			return nil, false, err
		}
		i += n
		if t == 0 {
			continue
		}
		if t > 0x06 {
			break
		}
		switch t {
		case 0x01:
			// PING
		case 0x02, 0x03:
			var rc uint64
			if _, n, err = readVarInt(data[i:]); err != nil {
				return nil, false, err
			}
			i += n
			if _, n, err = readVarInt(data[i:]); err != nil {
				return nil, false, err
			}
			i += n
			if rc, n, err = readVarInt(data[i:]); err != nil {
				return nil, false, err
			}
			i += n
			if _, n, err = readVarInt(data[i:]); err != nil {
				return nil, false, err
			}
			i += n
			for j := uint64(0); j < rc; j++ {
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, false, err
				}
				i += n
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, false, err
				}
				i += n
			}
			if t == 0x03 {
				for j := 0; j < 3; j++ {
					if _, n, err = readVarInt(data[i:]); err != nil {
						return nil, false, err
					}
					i += n
				}
			}
		case 0x04:
			for j := 0; j < 3; j++ {
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, false, err
				}
				i += n
			}
		case 0x05:
			for j := 0; j < 2; j++ {
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, false, err
				}
				i += n
			}
		case 0x06:
			var off, ln uint64
			if off, n, err = readVarInt(data[i:]); err != nil {
				return nil, false, err
			}
			i += n
			if ln, n, err = readVarInt(data[i:]); err != nil {
				return nil, false, err
			}
			i += n
			if i+int(ln) > len(data) {
				return nil, false, io.ErrUnexpectedEOF
			}
			ch, done := p.addCrypto(dcid, off, data[i:i+int(ln)])
			i += int(ln)
			parsed = true
			if done {
				return ch, true, nil
			}
		}
	}
	if !parsed {
		return nil, false, ErrNoCrypto
	}
	return nil, false, nil
}

// extractClientHelloInitial attempts to parse a QUIC Initial packet and
// returns the TLS ClientHello contained in CRYPTO frames. The input slice must
// contain exactly one QUIC packet.
func (p *Parser) extractClientHelloInitial(packet []byte) ([]byte, error) {
	if len(packet) < 6 {
		return nil, io.ErrUnexpectedEOF
	}
	if packet[0]&0x80 == 0 {
		return nil, errors.New("not client initial")
	}
	dcidLen := int(packet[5])
	if len(packet) < 6+dcidLen+1 {
		return nil, io.ErrUnexpectedEOF
	}
	dcid := packet[6 : 6+dcidLen]
	st := p.getState(dcid)
	pos := 6 + dcidLen
	scidLen := int(packet[pos])
	pos += 1 + scidLen
	tokLen, n, err := readVarInt(packet[pos:])
	if err != nil {
		return nil, err
	}
	pos += n + int(tokLen)
	length, n, err := readVarInt(packet[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	pnOffset := pos
	if pnOffset+4+16 > len(packet) {
		return nil, io.ErrUnexpectedEOF
	}
	if pnOffset+int(length) > len(packet) {
		return nil, io.ErrUnexpectedEOF
	}
	pnBytesOrig := packet[pnOffset : pnOffset+4]
	sample := packet[pnOffset+4 : pnOffset+4+16]
	version := binary.BigEndian.Uint32(packet[1:5])
	var salt []byte
	switch version {
	case 0x00000001:
		salt = saltV1
	case 0x6b3343cf, 0x709a50c4:
		salt = saltV2
	default:
		return nil, errors.New("unsupported QUIC version")
	}

	var lastErr error
	for i, attempt := range []struct {
		keyLen int
		alg    string
	}{{16, "aes"}, {32, "chacha"}} {
		key, iv, hp, err := deriveInitialKeys(dcid, salt, version, attempt.keyLen)
		if err != nil {
			return nil, err
		}
		mask := headerProtectionMask(hp, sample, attempt.alg)
		pnLen := computePNLen(packet[0], mask[0], version)
		first := packet[0]
		pnBytes := append([]byte(nil), pnBytesOrig...)
		applyHeaderProtectionMask(&first, pnBytes[:pnLen], mask)
		switch version {
		case 0x00000001:
			if first&0x0c != 0 {
				return nil, errors.New("reserved bits set")
			}
		case 0x6b3343cf, 0x709a50c4:
			if first&0x30 != 0 {
				return nil, errors.New("reserved bits set")
			}
		}
		typ, err := decodePacketType(first, version)
		if err != nil {
			return nil, err
		}
		if typ != 0 {
			return nil, errors.New("not client initial")
		}
		truncPN := decodePN(pnBytes[:pnLen])
		pnFull := reconstructPN(truncPN, pnLen, st.pn)
		header := append([]byte{first}, packet[1:pnOffset]...)
		header = append(header, pnBytes[:pnLen]...)
		payload := packet[pnOffset+pnLen : pnOffset+int(length)]
		if len(payload) < 16 {
			return nil, io.ErrUnexpectedEOF
		}
		plain, err := decryptInitial(key, iv, pnFull, header, payload)
		if err != nil {
			if i == 0 && err != nil && err.Error() == "cipher: message authentication failed" {
				lastErr = err
				continue
			}
			return nil, err
		}
		st.mu.Lock()
		if pnFull > st.pn {
			st.pn = pnFull
		}
		st.mu.Unlock()
		ch, done, err := p.parseCryptoFrames(dcid, plain)
		if err != nil {
			return nil, err
		}
		if !done {
			return nil, ErrNoCrypto
		}
		rec := make([]byte, 5+len(ch))
		rec[0] = 0x16
		rec[1] = 0x03
		rec[2] = 0x01
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(ch)))
		copy(rec[5:], ch)
		return rec, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("cipher: message authentication failed")

}

// longHeaderLen parses the header of a QUIC long-header packet and returns the
// total length of the packet. It supports Initial and Handshake packets. Retry
// packets are not supported and will return an error.
func longHeaderLen(b []byte) (int, error) {
	if len(b) < 6 {
		return 0, io.ErrUnexpectedEOF
	}
	version := binary.BigEndian.Uint32(b[1:5])
	typ := (b[0] >> 4) & 0x3
	if version == 0x6b3343cf || version == 0x709a50c4 {
		typ = b[0] & 0x03
	}
	if typ == 3 {
		return 0, errors.New("retry packet unsupported")
	}
	dcidLen := int(b[5])
	if len(b) < 6+dcidLen+1 {
		return 0, io.ErrUnexpectedEOF
	}
	pos := 6 + dcidLen
	scidLen := int(b[pos])
	pos += 1 + scidLen
	if len(b) < pos {
		return 0, io.ErrUnexpectedEOF
	}
	if typ == 0 {
		tokLen, n, err := readVarInt(b[pos:])
		if err != nil {
			return 0, err
		}
		pos += n + int(tokLen)
		if len(b) < pos {
			return 0, io.ErrUnexpectedEOF
		}
	}
	ln, n, err := readVarInt(b[pos:])
	if err != nil {
		return 0, err
	}
	pos += n
	if len(b) < pos {
		return 0, io.ErrUnexpectedEOF
	}
	return pos + int(ln), nil
}

// ExtractClientHello scans a UDP datagram that may contain multiple coalesced
// QUIC packets. Each long-header packet (bit 7 set) is processed independently
// and the first successfully decrypted ClientHello record is returned.
func (p *Parser) ExtractClientHello(datagram []byte) ([]byte, error) {
	var lastErr error
	for len(datagram) > 0 {
		if datagram[0]&0x80 == 0 {
			datagram = datagram[1:]
			continue
		}
		if datagram[0]&0x40 == 0 {
			lastErr = errors.New("fixed bit not set")
			break
		}
		ln, err := longHeaderLen(datagram)
		if err != nil {
			lastErr = err
			break
		}
		if ln > len(datagram) {
			lastErr = io.ErrUnexpectedEOF
			break
		}
		rec, err := p.extractClientHelloInitial(datagram[:ln])
		if err == nil {
			return rec, nil
		}
		lastErr = err
		datagram = datagram[ln:]
	}
	if lastErr == nil {
		lastErr = errors.New("not client initial")
	}
	return nil, lastErr
}

// The following wrappers provide backwards compatibility with the previous
// package-level API using a default parser instance.

func maybeGC() { defaultParser.maybeGC() }

func getState(dcid []byte) *connState { return defaultParser.getState(dcid) }

func extractClientHelloInitial(packet []byte) ([]byte, error) {
	return defaultParser.extractClientHelloInitial(packet)
}

// ExtractClientHello decrypts a QUIC Initial datagram (v1 or v2)
// and returns a TLS-style ClientHello record ready for fingerprinting.
func ExtractClientHello(datagram []byte) ([]byte, error) {
	return defaultParser.ExtractClientHello(datagram)
}
