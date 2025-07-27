package quic

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"testing"

	fp "github.com/0x4D31/fingerproxy/pkg/fingerprint"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
	"time"
)

const quicHelloHex = "1603010077010000730303a4b9f667f45a582a22e99360a97e87de5d3e2cbfe9a524b16ba423473d0a8a1d20e66b3ad64af1bf659ef90b50353f446932b385955ceddeee672ca7e820de025a0026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a1301130213030100000400390000"

func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeriveInitialKeysRFC9369(t *testing.T) {
	dcid := hexToBytes(t, "8394c8f03e515708")
	expKey := hexToBytes(t, "8b1a0bc121284290a29e0971b5cd045d")
	expIV := hexToBytes(t, "91f73e2351d8fa91660e909f")
	expHP := hexToBytes(t, "45b95e15235d6f45a6b19cbcb0294ba9")

	for _, ver := range []uint32{0x6b3343cf, 0x709a50c4} {
		t.Run(fmt.Sprintf("%08x", ver), func(t *testing.T) {
			key, iv, hp, err := deriveInitialKeys(dcid, saltV2, ver, 16)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, expKey) {
				t.Fatalf("key mismatch: got %x want %x", key, expKey)
			}
			if !bytes.Equal(iv, expIV) {
				t.Fatalf("iv mismatch: got %x want %x", iv, expIV)
			}
			if !bytes.Equal(hp, expHP) {
				t.Fatalf("hp mismatch: got %x want %x", hp, expHP)
			}
		})
	}
}

func TestDecodePacketType_V2Initial(t *testing.T) {
	first := byte(0b11000000)
	v2 := uint32(0x6b3343cf)
	typ, err := decodePacketType(first, v2)
	if err != nil || typ != 0 {
		t.Fatalf("want Initial (0), got %d (err=%v)", typ, err)
	}
}

func TestDecodePacketType_NotInitial(t *testing.T) {
	first := byte(0b11010000)
	v1 := uint32(0x00000001)
	typ, err := decodePacketType(first, v1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ == 0 {
		t.Fatal("expected non-Initial")
	}
}

func makeInitialPacket(t *testing.T, version []byte, pnLen int, salt []byte, ch []byte) []byte {
	t.Helper()
	plain := append([]byte{0x06, 0x00, byte(len(ch))}, ch...)
	dcid := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	scid := []byte{}
	fullPN := []byte{0x11, 0x22, 0x33, 0x44}
	pnBytes := fullPN[4-pnLen:]
	versionVal := binary.BigEndian.Uint32(version)
	first := byte(0xc0)
	if versionVal == 0x6b3343cf || versionVal == 0x709a50c4 {
		first |= byte(pnLen-1) << 2
	} else {
		first |= byte(pnLen - 1)
	}
	lenVal := uint64(len(plain) + pnLen + 16)
	lenBytes := encodeVarInt(lenVal)

	header := []byte{first}
	header = append(header, version...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00)
	header = append(header, lenBytes...)
	header = append(header, pnBytes...)

	key, iv, hp, err := deriveInitialKeys(dcid, salt, versionVal, 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnVal := decodePN(pnBytes)
	pnTmp := make([]byte, 8)
	binary.BigEndian.PutUint64(pnTmp, pnVal)
	for i := 0; i < len(nonce) && i < len(pnTmp); i++ {
		nonce[len(nonce)-1-i] ^= pnTmp[len(pnTmp)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)
	offset := 4 - pnLen
	sample := payload[offset : offset+16]
	firstMasked := first
	pnMasked := append([]byte(nil), pnBytes...)
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")

	packet := append([]byte{firstMasked}, version...)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	packet = append(packet, 0x00)
	packet = append(packet, lenBytes...)
	packet = append(packet, pnMasked...)
	packet = append(packet, payload...)
	return packet
}

func makeInitialPacketPN(t *testing.T, version []byte, pnLen int, salt []byte, ch []byte, pn uint64) []byte {
	dcid := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	return makeInitialPacketOffsetPN(t, version, pnLen, salt, dcid, 0, pn, ch)
}

func clearStates() {
	defaultParser.states.Range(func(k, v any) bool { defaultParser.states.Delete(k); return true })
	defaultParser.stateCount.Store(0)
}

func encodeVarInt(v uint64) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		return []byte{byte(0x40 | (v >> 8)), byte(v)}
	case v < 1073741824:
		return []byte{byte(0x80 | (v >> 24)), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		return []byte{byte(0xC0 | (v >> 56)), byte(v >> 48), byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

func makeInitialPacketOffset(t *testing.T, version []byte, pnLen int, salt []byte, dcid []byte, off uint64, data []byte) []byte {
	t.Helper()
	plain := []byte{0x06}
	plain = append(plain, encodeVarInt(off)...)
	plain = append(plain, encodeVarInt(uint64(len(data)))...)
	plain = append(plain, data...)

	scid := []byte{}
	fullPN := []byte{0x11, 0x22, 0x33, 0x44}
	pnBytes := fullPN[4-pnLen:]
	versionVal := binary.BigEndian.Uint32(version)
	first := byte(0xc0)
	if versionVal == 0x6b3343cf || versionVal == 0x709a50c4 {
		first |= byte(pnLen-1) << 2
	} else {
		first |= byte(pnLen - 1)
	}
	lenVal := uint64(len(plain) + pnLen + 16)
	lenBytes := encodeVarInt(lenVal)

	header := []byte{first}
	header = append(header, version...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00)
	header = append(header, lenBytes...)
	header = append(header, pnBytes...)

	key, iv, hp, err := deriveInitialKeys(dcid, salt, versionVal, 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnVal := decodePN(pnBytes)
	pnTmp := make([]byte, 8)
	binary.BigEndian.PutUint64(pnTmp, pnVal)
	for i := 0; i < len(nonce) && i < len(pnTmp); i++ {
		nonce[len(nonce)-1-i] ^= pnTmp[len(pnTmp)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)
	offset := 4 - pnLen
	sample := payload[offset : offset+16]
	firstMasked := first
	pnMasked := append([]byte(nil), pnBytes...)
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")

	packet := append([]byte{firstMasked}, version...)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	packet = append(packet, 0x00)
	packet = append(packet, lenBytes...)
	packet = append(packet, pnMasked...)
	packet = append(packet, payload...)
	return packet
}

func makeInitialPacketOffsetPN(t *testing.T, version []byte, pnLen int, salt []byte, dcid []byte, off uint64, pn uint64, data []byte) []byte {
	t.Helper()
	plain := []byte{0x06}
	plain = append(plain, encodeVarInt(off)...)
	plain = append(plain, encodeVarInt(uint64(len(data)))...)
	plain = append(plain, data...)

	scid := []byte{}
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[pnLen-1-i] = byte(pn >> (8 * i))
	}
	versionVal := binary.BigEndian.Uint32(version)
	first := byte(0xc0)
	if versionVal == 0x6b3343cf || versionVal == 0x709a50c4 {
		first |= byte(pnLen-1) << 2
	} else {
		first |= byte(pnLen - 1)
	}
	lenVal := uint64(len(plain) + pnLen + 16)
	lenBytes := encodeVarInt(lenVal)

	header := []byte{first}
	header = append(header, version...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00)
	header = append(header, lenBytes...)
	header = append(header, pnBytes...)

	key, iv, hp, err := deriveInitialKeys(dcid, salt, versionVal, 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnTmp := make([]byte, 8)
	binary.BigEndian.PutUint64(pnTmp, pn)
	for i := 0; i < len(nonce) && i < len(pnTmp); i++ {
		nonce[len(nonce)-1-i] ^= pnTmp[len(pnTmp)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)
	offset := 4 - pnLen
	sample := payload[offset : offset+16]
	firstMasked := first
	pnMasked := append([]byte(nil), pnBytes...)
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")

	packet := append([]byte{firstMasked}, version...)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	packet = append(packet, 0x00)
	packet = append(packet, lenBytes...)
	packet = append(packet, pnMasked...)
	packet = append(packet, payload...)
	return packet
}

// extractClientHelloFrames is a helper used in tests to parse CRYPTO frames
// from a QUIC Initial payload and assemble the contained ClientHello bytes.
func extractClientHelloFrames(data []byte) ([]byte, int, error) {
	i := 0
	var out []byte
	expected := uint64(0)
	parsed := false

	for i < len(data) {
		pos := i
		t, n, err := readVarInt(data[i:])
		if err != nil {
			return nil, i, err
		}
		i += n
		if t == 0 {
			continue
		}
		if t > 0x06 {
			i = pos
			break
		}

		switch t {
		case 0x01:
			// PING: no payload
		case 0x02, 0x03:
			// ACK or ACK_ECN
			var rc uint64
			if _, n, err = readVarInt(data[i:]); err != nil {
				return nil, i, err
			}
			i += n
			if _, n, err = readVarInt(data[i:]); err != nil {
				return nil, i, err
			}
			i += n
			if rc, n, err = readVarInt(data[i:]); err != nil {
				return nil, i, err
			}
			i += n
			if _, n, err = readVarInt(data[i:]); err != nil {
				return nil, i, err
			}
			i += n
			for j := uint64(0); j < rc; j++ {
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, i, err
				}
				i += n
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, i, err
				}
				i += n
			}
			if t == 0x03 {
				for j := 0; j < 3; j++ {
					if _, n, err = readVarInt(data[i:]); err != nil {
						return nil, i, err
					}
					i += n
				}
			}
		case 0x04:
			// RESET_STREAM
			for j := 0; j < 3; j++ {
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, i, err
				}
				i += n
			}
		case 0x05:
			// STOP_SENDING
			for j := 0; j < 2; j++ {
				if _, n, err = readVarInt(data[i:]); err != nil {
					return nil, i, err
				}
				i += n
			}
		case 0x06:
			var off, ln uint64
			if off, n, err = readVarInt(data[i:]); err != nil {
				return nil, i, err
			}
			i += n
			if ln, n, err = readVarInt(data[i:]); err != nil {
				return nil, i, err
			}
			i += n
			if off != expected || i+int(ln) > len(data) {
				return nil, i, errors.New("invalid crypto frame")
			}
			out = append(out, data[i:i+int(ln)]...)
			i += int(ln)
			expected += ln
			parsed = true
		}
	}

	if !parsed {
		return nil, i, ErrNoCrypto
	}
	return out, i, nil
}

func TestExtractJA4(t *testing.T) {
	data := &metadata.Metadata{ClientHelloRecord: hexToBytes(t, quicHelloHex), IsQUIC: true}
	fpstr, err := fp.JA4Fingerprint(data)
	if err != nil {
		t.Fatalf("ja4: %v", err)
	}
	if fpstr == "" || fpstr[0] != 'q' {
		t.Fatalf("expected JA4 q-prefix, got %s", fpstr)
	}
}

func TestDecryptInitialShortPN(t *testing.T) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	iv := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b}
	pn := uint64(0xdecaf)
	header := []byte{0x01, 0x02, 0x03}
	plain := []byte("finch")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}

	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pnBytes, pn)
	for i := 0; i < len(nonce) && i < len(pnBytes); i++ {
		nonce[len(nonce)-1-i] ^= pnBytes[len(pnBytes)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)

	out, err := decryptInitial(key, iv, pn, header, payload)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(out) != string(plain) {
		t.Fatalf("decrypt mismatch: got %x want %x", out, plain)
	}
}

func TestExtractClientHelloInitialHeader(t *testing.T) {
	ch := []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	plain := append([]byte{0x06, 0x00, byte(len(ch))}, ch...)
	dcid := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	scid := []byte{}
	pn := uint64(0x11223344)
	pnBytes := []byte{0x11, 0x22, 0x33, 0x44}
	first := byte(0xc3)
	version := []byte{0x00, 0x00, 0x00, 0x01}
	length := byte(len(plain) + len(pnBytes) + 16)
	header := []byte{first}
	header = append(header, version...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00)
	header = append(header, length)
	header = append(header, pnBytes...)

	key, iv, hp, err := deriveInitialKeys(dcid, saltV1, binary.BigEndian.Uint32(version), 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnTmp := make([]byte, 8)
	binary.BigEndian.PutUint64(pnTmp, pn)
	for i := 0; i < len(nonce) && i < len(pnTmp); i++ {
		nonce[len(nonce)-1-i] ^= pnTmp[len(pnTmp)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)
	sample := payload[:16]
	firstMasked := first
	pnMasked := append([]byte(nil), pnBytes...)
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")
	packet := append([]byte{firstMasked}, version...)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	packet = append(packet, 0x00)
	packet = append(packet, length)
	packet = append(packet, pnMasked...)
	packet = append(packet, payload...)

	t.Logf("packet: %x", packet)
	rec, err := ExtractClientHello(packet)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	exp := make([]byte, 5+len(ch))
	exp[0] = 0x16
	exp[1] = 0x03
	exp[2] = 0x01
	binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
	copy(exp[5:], ch)
	if !bytes.Equal(rec, exp) {
		t.Fatalf("mismatch: got %x want %x", rec, exp)
	}
}

func TestExtractClientHelloInitialHeaderV2(t *testing.T) {
	t.Skip("QUIC v2 unsupported")
	ch := []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	plain := append([]byte{0x06, 0x00, byte(len(ch))}, ch...)
	dcid := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	scid := []byte{}
	pn := uint64(0x11223344)
	pnBytes := []byte{0x11, 0x22, 0x33, 0x44}
	first := byte(0xcc)
	version := []byte{0x6b, 0x33, 0x43, 0xcf}
	length := byte(len(plain) + len(pnBytes) + 16)
	header := []byte{first}
	header = append(header, version...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00)
	header = append(header, length)
	header = append(header, pnBytes...)

	key, iv, hp, err := deriveInitialKeys(dcid, saltV2, binary.BigEndian.Uint32(version), 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnTmp := make([]byte, 8)
	binary.BigEndian.PutUint64(pnTmp, pn)
	for i := 0; i < len(nonce) && i < len(pnTmp); i++ {
		nonce[len(nonce)-1-i] ^= pnTmp[len(pnTmp)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)
	sample := payload[:16]
	firstMasked := first
	pnMasked := append([]byte(nil), pnBytes...)
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")
	packet := append([]byte{firstMasked}, version...)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	packet = append(packet, 0x00)
	packet = append(packet, length)
	packet = append(packet, pnMasked...)
	packet = append(packet, payload...)

	rec, err := ExtractClientHello(packet)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	exp := make([]byte, 5+len(ch))
	exp[0] = 0x16
	exp[1] = 0x03
	exp[2] = 0x01
	binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
	copy(exp[5:], ch)
	if !bytes.Equal(rec, exp) {
		t.Fatalf("mismatch: got %x want %x", rec, exp)
	}
}

func TestExtractClientHelloPNLengths(t *testing.T) {
	ch := []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	version := []byte{0x00, 0x00, 0x00, 0x01}
	for pnLen := 1; pnLen <= 4; pnLen++ {
		t.Run(fmt.Sprintf("pn%d", pnLen), func(t *testing.T) {
			packet := makeInitialPacket(t, version, pnLen, saltV1, ch)
			rec, err := ExtractClientHello(packet)
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			exp := make([]byte, 5+len(ch))
			exp[0] = 0x16
			exp[1] = 0x03
			exp[2] = 0x01
			binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
			copy(exp[5:], ch)
			if !bytes.Equal(rec, exp) {
				t.Fatalf("mismatch: got %x want %x", rec, exp)
			}
		})
	}
}

func TestExtractClientHelloPNLengthsV2(t *testing.T) {
	ch := []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	versions := [][]byte{{0x6b, 0x33, 0x43, 0xcf}, {0x70, 0x9a, 0x50, 0xc4}}
	for _, version := range versions {
		versionVal := binary.BigEndian.Uint32(version)
		t.Run(fmt.Sprintf("ver%x", versionVal), func(t *testing.T) {
			for pnLen := 1; pnLen <= 4; pnLen++ {
				t.Run(fmt.Sprintf("pn%d", pnLen), func(t *testing.T) {
					packet := makeInitialPacket(t, version, pnLen, saltV2, ch)
					rec, err := extractClientHelloInitial(packet)
					if err != nil {
						t.Fatalf("extract: %v", err)
					}
					exp := make([]byte, 5+len(ch))
					exp[0] = 0x16
					exp[1] = 0x03
					exp[2] = 0x01
					binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
					copy(exp[5:], ch)
					if !bytes.Equal(rec, exp) {
						t.Fatalf("mismatch: got %x want %x", rec, exp)
					}
				})
			}
		})
	}
}

func TestComputePNLenReconstructV2(t *testing.T) {
	ch := []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	versions := []struct {
		b   []byte
		val uint32
	}{
		{[]byte{0x6b, 0x33, 0x43, 0xcf}, 0x6b3343cf},
		{[]byte{0x70, 0x9a, 0x50, 0xc4}, 0x709a50c4},
	}
	pnVal := uint64(0x11223344)
	dcid := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	for _, v := range versions {
		for pnLen := 1; pnLen <= 4; pnLen++ {
			t.Run(fmt.Sprintf("ver%x_pn%d", v.val, pnLen), func(t *testing.T) {
				packet := makeInitialPacketPN(t, v.b, pnLen, saltV2, ch, pnVal)

				pos := 1 + 4
				dl := int(packet[pos])
				pos++
				pos += dl
				sl := int(packet[pos])
				pos++
				pos += sl
				_, n, err := readVarInt(packet[pos:])
				if err != nil {
					t.Fatalf("token varint: %v", err)
				}
				pos += n
				_, n, err = readVarInt(packet[pos:])
				if err != nil {
					t.Fatalf("len varint: %v", err)
				}
				pos += n

				pnOffset := pos
				sample := packet[pnOffset+4 : pnOffset+4+16]
				_, _, hp, err := deriveInitialKeys(dcid, saltV2, v.val, 16)
				if err != nil {
					t.Fatalf("derive keys: %v", err)
				}
				mask := headerProtectionMask(hp, sample, "aes")
				got := computePNLen(packet[0], mask[0], v.val)
				if got != pnLen {
					t.Fatalf("computePNLen=%d want %d", got, pnLen)
				}
				first := packet[0]
				pnBytes := append([]byte(nil), packet[pnOffset:pnOffset+4]...)
				applyHeaderProtectionMask(&first, pnBytes[:pnLen], mask)
				trunc := decodePN(pnBytes[:pnLen])
				full := reconstructPN(trunc, pnLen, pnVal-1)
				if full != pnVal {
					t.Fatalf("pn reconstruct=%x want %x", full, pnVal)
				}
			})
		}
	}
}

func TestHeaderUnprotectValidInitial(t *testing.T) {
	plain := []byte{0x01, 0x02, 0x03, 0x04}
	dcid := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	scid := []byte{}
	pn := uint64(0xa1b2c3d4)
	pnBytes := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	first := byte(0xc3)
	version := []byte{0x00, 0x00, 0x00, 0x01}
	length := byte(len(plain) + len(pnBytes) + 16)

	header := []byte{first}
	header = append(header, version...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00)
	header = append(header, length)
	header = append(header, pnBytes...)

	key, iv, hp, err := deriveInitialKeys(dcid, saltV1, binary.BigEndian.Uint32(version), 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnTmp := make([]byte, 8)
	binary.BigEndian.PutUint64(pnTmp, pn)
	for i := 0; i < len(nonce) && i < len(pnTmp); i++ {
		nonce[len(nonce)-1-i] ^= pnTmp[len(pnTmp)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)
	if len(payload) < 16 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	sample := payload[:16]
	firstMasked := first
	pnMasked := append([]byte(nil), pnBytes...)
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")

	// unprotect
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")
	if firstMasked != first || !bytes.Equal(pnMasked, pnBytes) {
		t.Fatalf("unprotection failed: %x %x", firstMasked, pnMasked)
	}
}

func TestDecodePacketType_HPRemovalV2(t *testing.T) {
	plain := []byte{0x01, 0x02, 0x03, 0x04}
	dcid := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	scid := []byte{}
	pn := uint64(0xa1b2c3d4)
	pnBytes := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	first := byte(0xc0 | (3 << 2))
	version := []byte{0x6b, 0x33, 0x43, 0xcf}
	length := byte(len(plain) + len(pnBytes) + 16)

	header := []byte{first}
	header = append(header, version...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00)
	header = append(header, length)
	header = append(header, pnBytes...)

	key, iv, hp, err := deriveInitialKeys(dcid, saltV2, binary.BigEndian.Uint32(version), 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnTmp := make([]byte, 8)
	binary.BigEndian.PutUint64(pnTmp, pn)
	for i := 0; i < len(nonce) && i < len(pnTmp); i++ {
		nonce[len(nonce)-1-i] ^= pnTmp[len(pnTmp)-1-i]
	}
	payload := aead.Seal(nil, nonce, plain, header)
	sample := payload[:16]
	firstMasked := first
	pnMasked := append([]byte(nil), pnBytes...)
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")

	// unprotect
	applyHeaderProtection(&firstMasked, pnMasked, hp, sample, "aes")
	if firstMasked&0x03 != 0 {
		t.Fatalf("type bits corrupted: %02x", firstMasked)
	}
}

func dummyInitialPacket(t *testing.T, version []byte, length byte, payloadLen int) []byte {
	t.Helper()
	first := byte(0xc3)
	dcid := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	scid := []byte{}
	pnBytes := []byte{0x11, 0x22, 0x33, 0x44}

	packet := []byte{first}
	packet = append(packet, version...)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	packet = append(packet, 0x00)
	packet = append(packet, length)
	packet = append(packet, pnBytes...)
	packet = append(packet, bytes.Repeat([]byte{0}, payloadLen)...)
	return packet
}

func dummyHandshakePacket(t *testing.T, version []byte, payloadLen int) []byte {
	t.Helper()
	first := byte(0xe3)
	dcid := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	scid := []byte{}
	pnBytes := []byte{0x11, 0x22, 0x33, 0x44}
	length := byte(len(pnBytes) + payloadLen)

	packet := []byte{first}
	packet = append(packet, version...)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	packet = append(packet, length)
	packet = append(packet, pnBytes...)
	packet = append(packet, bytes.Repeat([]byte{0}, payloadLen)...)
	return packet
}

func TestExtractClientHelloTruncatedPacket(t *testing.T) {
	packet := dummyInitialPacket(t, []byte{0x00, 0x00, 0x00, 0x01}, 25, 10)
	_, err := ExtractClientHello(packet)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestExtractClientHelloShortPayload(t *testing.T) {
	packet := dummyInitialPacket(t, []byte{0x00, 0x00, 0x00, 0x01}, 19, 19)
	_, err := ExtractClientHello(packet)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestExtractClientHelloFixedBitCleared(t *testing.T) {
	ch := []byte{0x01}
	version := []byte{0x00, 0x00, 0x00, 0x01}
	packet := makeInitialPacket(t, version, 4, saltV1, ch)
	packet[0] &^= 0x40
	_, err := ExtractClientHello(packet)
	if err == nil || err.Error() != "fixed bit not set" {
		t.Fatalf("expected fixed bit error, got %v", err)
	}
}

func corruptReservedBits(t *testing.T, packet []byte, mask byte) []byte {
	version := binary.BigEndian.Uint32(packet[1:5])
	pos := 5
	dcidLen := int(packet[pos])
	pos++
	dcid := packet[pos : pos+dcidLen]
	pos += dcidLen
	scidLen := int(packet[pos])
	pos++
	pos += scidLen
	tokLen, n, err := readVarInt(packet[pos:])
	if err != nil {
		t.Fatalf("tok varint: %v", err)
	}
	pos += n + int(tokLen)
	_, n, err = readVarInt(packet[pos:])
	if err != nil {
		t.Fatalf("len varint: %v", err)
	}
	pos += n
	pnOffset := pos
	sample := packet[pnOffset+4 : pnOffset+4+16]
	salt := saltV1
	switch version {
	case 0x6b3343cf, 0x709a50c4:
		salt = saltV2
	}
	_, _, hp, err := deriveInitialKeys(dcid, salt, version, 16)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	m := headerProtectionMask(hp, sample, "aes")
	pnLen := computePNLen(packet[0], m[0], version)
	first := packet[0]
	pnBytes := append([]byte(nil), packet[pnOffset:pnOffset+pnLen]...)
	applyHeaderProtectionMask(&first, pnBytes, m)
	first |= mask
	applyHeaderProtectionMask(&first, pnBytes, m)
	out := append([]byte(nil), packet...)
	out[0] = first
	copy(out[pnOffset:], pnBytes)
	return out
}

func TestExtractClientHelloReservedBits(t *testing.T) {
	clearStates()
	ch := []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	version := []byte{0x00, 0x00, 0x00, 0x01}
	packet := makeInitialPacket(t, version, 4, saltV1, ch)

	if _, err := ExtractClientHello(packet); err != nil {
		t.Fatalf("extract valid: %v", err)
	}

	bad := corruptReservedBits(t, packet, 0x0c)
	_, err := ExtractClientHello(bad)
	if err == nil || err.Error() != "reserved bits set" {
		t.Fatalf("expected reserved bits error, got %v", err)
	}
}

func TestExtractClientHelloReservedBitsV2(t *testing.T) {
	clearStates()
	ch := []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	version := []byte{0x6b, 0x33, 0x43, 0xcf}
	packet := makeInitialPacket(t, version, 4, saltV2, ch)

	if _, err := extractClientHelloInitial(packet); err != nil {
		t.Fatalf("extract valid: %v", err)
	}

	bad := corruptReservedBits(t, packet, 0x30)
	_, err := extractClientHelloInitial(bad)
	if err == nil || err.Error() != "reserved bits set" {
		t.Fatalf("expected reserved bits error, got %v", err)
	}
}

func TestExtractClientHelloMultiplePackets(t *testing.T) {
	ch := []byte{0x01, 0x00, 0x00, 0x02, 0x01, 0x02}
	version := []byte{0x00, 0x00, 0x00, 0x01}

	t.Run("first", func(t *testing.T) {
		p1 := makeInitialPacket(t, version, 4, saltV1, ch)
		p2 := dummyHandshakePacket(t, version, 10)
		datagram := append(p1, p2...)
		rec, err := ExtractClientHello(datagram)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		exp := make([]byte, 5+len(ch))
		exp[0] = 0x16
		exp[1] = 0x03
		exp[2] = 0x01
		binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
		copy(exp[5:], ch)
		if !bytes.Equal(rec, exp) {
			t.Fatalf("mismatch: got %x want %x", rec, exp)
		}
	})

	t.Run("second", func(t *testing.T) {
		p1 := dummyHandshakePacket(t, version, 10)
		p2 := makeInitialPacket(t, version, 4, saltV1, ch)
		datagram := append(p1, p2...)
		rec, err := ExtractClientHello(datagram)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		exp := make([]byte, 5+len(ch))
		exp[0] = 0x16
		exp[1] = 0x03
		exp[2] = 0x01
		binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
		copy(exp[5:], ch)
		if !bytes.Equal(rec, exp) {
			t.Fatalf("mismatch: got %x want %x", rec, exp)
		}
	})
}

func TestExtractClientHelloShortHeaderPrecedesInitial(t *testing.T) {
	ch := []byte{0x01, 0x00, 0x00, 0x02, 0x01, 0x02}
	version := []byte{0x00, 0x00, 0x00, 0x01}
	short := []byte{0x40, 0x00, 0x00}
	p := makeInitialPacket(t, version, 4, saltV1, ch)
	datagram := append(short, p...)
	rec, err := ExtractClientHello(datagram)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	exp := make([]byte, 5+len(ch))
	exp[0] = 0x16
	exp[1] = 0x03
	exp[2] = 0x01
	binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
	copy(exp[5:], ch)
	if !bytes.Equal(rec, exp) {
		t.Fatalf("mismatch: got %x want %x", rec, exp)
	}
}

func TestExtractClientHelloFramesMultiple(t *testing.T) {
	// two consecutive CRYPTO frames with offsets 0 and 2
	data := []byte{
		0x06, 0x00, 0x02, 0x01, 0x02,
		0x06, 0x02, 0x03, 0x03, 0x04, 0x05,
	}
	out, _, err := extractClientHelloFrames(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	exp := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(out, exp) {
		t.Fatalf("mismatch: got %x want %x", out, exp)
	}
}

func TestExtractClientHelloFramesOffsetMismatch(t *testing.T) {
	// second frame has unexpected offset
	data := []byte{
		0x06, 0x00, 0x01, 0x01,
		0x06, 0x03, 0x01, 0x02,
	}
	_, _, err := extractClientHelloFrames(data)
	if err == nil || err.Error() != "invalid crypto frame" {
		t.Fatalf("expected invalid crypto frame error, got %v", err)
	}
}

func TestPaddingAndCrypto(t *testing.T) {
	data := []byte{
		0x00, 0x00,
		0x06, 0x00, 0x01, 0xaa,
		0x00,
		0x06, 0x01, 0x01, 0xbb,
	}
	out, _, err := extractClientHelloFrames(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	exp := []byte{0xaa, 0xbb}
	if !bytes.Equal(out, exp) {
		t.Fatalf("mismatch: got %x want %x", out, exp)
	}
}

func TestStopsOnUnsupported(t *testing.T) {
	data := []byte{
		0x06, 0x00, 0x01, 0xaa,
		0x07,
	}
	out, n, err := extractClientHelloFrames(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if n != 4 {
		t.Fatalf("next pos %d", n)
	}
	exp := []byte{0xaa}
	if !bytes.Equal(out, exp) {
		t.Fatalf("mismatch: got %x want %x", out, exp)
	}
}

func TestOnlyPadding(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00}
	_, _, err := extractClientHelloFrames(data)
	if !errors.Is(err, ErrNoCrypto) {
		t.Fatalf("expected ErrNoCrypto, got %v", err)
	}
}

func TestClientHelloSplitAcrossInitials(t *testing.T) {
	clearStates()
	ch := make([]byte, 1162)
	ch[0] = 0x01
	ch[1] = 0x00
	ch[2] = 0x04
	ch[3] = 0x86
	for i := 4; i < len(ch); i++ {
		ch[i] = byte(i)
	}
	part1 := ch[:600]
	part2 := ch[600:]
	version := []byte{0x00, 0x00, 0x00, 0x01}
	dcid := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	p1 := makeInitialPacketOffset(t, version, 4, saltV1, dcid, 0, part1)
	if _, err := ExtractClientHello(p1); !errors.Is(err, ErrNoCrypto) {
		t.Fatalf("expected ErrNoCrypto, got %v", err)
	}
	p2 := makeInitialPacketOffset(t, version, 4, saltV1, dcid, 600, part2)
	rec, err := ExtractClientHello(p2)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(rec) != 5+len(ch) {
		t.Fatalf("length %d", len(rec))
	}
	if rec[5] != 0x01 {
		t.Fatalf("msgType %02x", rec[5])
	}
}

func TestDifferentConnectionsIsolated(t *testing.T) {
	clearStates()
	ch := make([]byte, 1162)
	ch[0] = 0x01
	ch[1] = 0x00
	ch[2] = 0x04
	ch[3] = 0x86
	for i := 4; i < len(ch); i++ {
		ch[i] = byte(i)
	}
	part1 := ch[:600]
	part2 := ch[600:]
	version := []byte{0x00, 0x00, 0x00, 0x01}
	dcidA := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	dcidB := []byte{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02}

	p1a := makeInitialPacketOffset(t, version, 4, saltV1, dcidA, 0, part1)
	_, _ = ExtractClientHello(p1a)
	p1b := makeInitialPacketOffset(t, version, 4, saltV1, dcidB, 0, part1)
	_, _ = ExtractClientHello(p1b)

	p2b := makeInitialPacketOffset(t, version, 4, saltV1, dcidB, 600, part2)
	recB, err := ExtractClientHello(p2b)
	if err != nil {
		t.Fatalf("extract B: %v", err)
	}
	if recB[5] != 0x01 {
		t.Fatalf("type B %02x", recB[5])
	}

	p2a := makeInitialPacketOffset(t, version, 4, saltV1, dcidA, 600, part2)
	recA, err := ExtractClientHello(p2a)
	if err != nil {
		t.Fatalf("extract A: %v", err)
	}
	if recA[5] != 0x01 {
		t.Fatalf("type A %02x", recA[5])
	}
}

func TestEvictionAfterParse(t *testing.T) {
	clearStates()
	ch := make([]byte, 20)
	ch[0] = 0x01
	ch[1] = 0x00
	ch[2] = 0x00
	ch[3] = 0x10
	for i := 4; i < len(ch); i++ {
		ch[i] = byte(i)
	}
	dcid := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01}
	p1 := makeInitialPacketOffset(t, []byte{0x00, 0x00, 0x00, 0x01}, 4, saltV1, dcid, 0, ch)
	_, _ = ExtractClientHello(p1)
	count := 0
	defaultParser.states.Range(func(k, v any) bool { count++; return true })
	if count != 0 {
		t.Fatalf("expected eviction, map size %d", count)
	}
}

func TestDuplicateCryptoFragmentsIgnored(t *testing.T) {
	clearStates()
	rec := hexToBytes(t, quicHelloHex)
	ch := rec[5:]
	part1 := ch[:50]
	part2 := ch[50:]
	dcid := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02}
	version := []byte{0x00, 0x00, 0x00, 0x01}

	p1 := makeInitialPacketOffset(t, version, 4, saltV1, dcid, 0, part1)
	if _, err := ExtractClientHello(p1); !errors.Is(err, ErrNoCrypto) {
		t.Fatalf("expected ErrNoCrypto, got %v", err)
	}
	if _, err := ExtractClientHello(p1); !errors.Is(err, ErrNoCrypto) {
		t.Fatalf("expected ErrNoCrypto, got %v", err)
	}
	p2 := makeInitialPacketOffset(t, version, 4, saltV1, dcid, uint64(len(part1)), part2)
	recOut, err := ExtractClientHello(p2)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(recOut) != 5+len(ch) {
		t.Fatalf("length %d", len(recOut))
	}
	if recOut[5] != 0x01 {
		t.Fatalf("msgType %02x", recOut[5])
	}
}

func TestTwoInitialsUpdatePN(t *testing.T) {
	clearStates()
	rec := hexToBytes(t, quicHelloHex)
	ch := rec[5:]
	part1 := ch[:50]
	part2 := ch[50:]
	version := []byte{0x00, 0x00, 0x00, 0x01}
	dcid := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x03}

	p1 := makeInitialPacketOffsetPN(t, version, 1, saltV1, dcid, 0, 0, part1)
	p2 := makeInitialPacketOffsetPN(t, version, 1, saltV1, dcid, uint64(len(part1)), 1, part2)
	datagram := append(p1, p2...)

	recOut, err := ExtractClientHello(datagram)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(recOut) != 5+len(ch) {
		t.Fatalf("length %d", len(recOut))
	}
	if recOut[5] != 0x01 {
		t.Fatalf("msgType %02x", recOut[5])
	}
}

func TestPacketNumberReconstruction(t *testing.T) {
	clearStates()
	ch := []byte{0x01, 0x00, 0x00, 0x01, 0xaa}
	version := []byte{0x00, 0x00, 0x00, 0x01}
	pnVal := uint64(0x259)
	packet := makeInitialPacketPN(t, version, 1, saltV1, ch, pnVal)
	dcid := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	st := getState(dcid)
	st.pn = pnVal - 1
	rec, err := ExtractClientHello(packet)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	exp := make([]byte, 5+len(ch))
	exp[0] = 0x16
	exp[1] = 0x03
	exp[2] = 0x01
	binary.BigEndian.PutUint16(exp[3:5], uint16(len(ch)))
	copy(exp[5:], ch)
	if !bytes.Equal(rec, exp) {
		t.Fatalf("mismatch: got %x want %x", rec, exp)
	}
}

func TestStateMapGC(t *testing.T) {
	clearStates()
	oldLimit := defaultParser.stateLimit
	defaultParser.stateLimit = 1
	defer func() { defaultParser.stateLimit = oldLimit }()

	dcidOld := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	st := getState(dcidOld)
	st.ts = time.Now().Add(-defaultParser.stateTTL - time.Second)

	dcidNew := []byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	getState(dcidNew)

	maybeGC()

	count := 0
	defaultParser.states.Range(func(k, v any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("expected 1 state after GC, got %d", count)
	}
}

func TestHPChaCha20(t *testing.T) {
	hpKey := hexToBytes(t, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
	sample := hexToBytes(t, "5e5cd55c41f69080575d7999c25a5bfb")
	first := byte(0x4c)
	pn := []byte{0xfe, 0x41, 0x89}
	applyHeaderProtection(&first, pn, hpKey, sample, "chacha")
	hdr := append([]byte{first}, pn...)
	exp := hexToBytes(t, "4200bff4")
	if !bytes.Equal(hdr, exp) {
		t.Fatalf("header mismatch: got %x want %x", hdr, exp)
	}
}

func TestAEADChaCha20(t *testing.T) {
	key := hexToBytes(t, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
	iv := hexToBytes(t, "e0459b3474bdd0e44a41c144")
	hpKey := hexToBytes(t, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
	packet := hexToBytes(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")

	first := packet[0]
	pn := append([]byte(nil), packet[1:4]...)
	sample := packet[5:21]
	applyHeaderProtection(&first, pn, hpKey, sample, "chacha")
	if hdr := append([]byte{first}, pn...); !bytes.Equal(hdr, hexToBytes(t, "4200bff4")) {
		t.Fatalf("header mismatch: %x", hdr)
	}

	pnVal := uint64(654360564)
	header := append([]byte{first}, pn...)
	payload := packet[4:]
	plain, err := decryptInitial(key, iv, pnVal, header, payload)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(plain) == 0 || plain[0] != 0x01 {
		t.Fatalf("unexpected plaintext %x", plain)
	}
}

func FuzzHPAndAEAD(f *testing.F) {
	f.Fuzz(func(t *testing.T, b1, b2 []byte) {
		if len(b1) == 0 || len(b2) < 16 {
			return
		}
		keyLen := 16
		if b1[0]&1 == 1 {
			keyLen = 32
		}
		hpKey := make([]byte, keyLen)
		copy(hpKey, b1)
		if len(hpKey) < keyLen {
			hpKey = append(hpKey, make([]byte, keyLen-len(hpKey))...)
		}
		sample := make([]byte, 16)
		copy(sample, b2)
		first := byte(0x40)
		pn := []byte{0x01, 0x02, 0x03, 0x04}
		alg := "aes"
		if keyLen == 32 {
			alg = "chacha"
		}
		applyHeaderProtection(&first, pn, hpKey, sample, alg)
		applyHeaderProtection(&first, pn, hpKey, sample, alg)

		key := make([]byte, keyLen)
		copy(key, b1)
		if len(key) < keyLen {
			key = append(key, make([]byte, keyLen-len(key))...)
		}
		header := []byte{0x01}
		plain := []byte{0xaa}
		var aead cipher.AEAD
		var err error
		if keyLen == 16 {
			var block cipher.Block
			block, err = aes.NewCipher(key)
			if err != nil {
				t.Fatalf("cipher: %v", err)
			}
			aead, err = cipher.NewGCM(block)
		} else {
			aead, err = chacha20poly1305.New(key)
		}
		if err != nil {
			t.Fatalf("aead: %v", err)
		}
		nonce := make([]byte, 12)
		ct := aead.Seal(nil, nonce, plain, header)
		if _, err := decryptInitial(key, nonce, 0, header, ct); err != nil {
			t.Fatalf("decrypt: %v", err)
		}
	})
}
