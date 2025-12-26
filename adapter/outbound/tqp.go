package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"
)

// TQP is a TianQue Protocol adapter
type TQP struct {
	*Base
	option *TQPOption
	dialer proxydialer.SingDialer
}

// TQPOption contains options for TQP connections
type TQPOption struct {
	BasicOption
	Name              string   `proxy:"name"`
	Server            string   `proxy:"server"`
	Port              int      `proxy:"port"`
	UUID              string   `proxy:"uuid"`
	SNI               string   `proxy:"servername,omitempty"`
	SkipCertVerify    bool     `proxy:"skip-cert-verify,omitempty"`
	ClientFingerprint string   `proxy:"client-fingerprint,omitempty"`
	ALPN              []string `proxy:"alpn,omitempty"`
}

// TQP Magic bytes
var tqpMagic = []byte{0x54, 0x51, 0x50, 0x01} // "TQP\x01"

// DialContext implements C.ProxyAdapter
func (t *TQP) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.dialTLS(ctx)
	if err != nil {
		return nil, err
	}

	// Perform TQP handshake
	err = t.clientHandshake(c, metadata)
	if err != nil {
		c.Close()
		return nil, err
	}

	return NewConn(c, t), nil
}

// dialTLS establishes a TLS connection to the server
func (t *TQP) dialTLS(ctx context.Context) (net.Conn, error) {
	host := t.option.Server
	port := t.option.Port
	sni := t.option.SNI
	if sni == "" {
		sni = host
	}

	// Create base TCP connection
	tcpConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), t.DialOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	// Wrap with TLS
	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: t.option.SkipCertVerify,
		NextProtos:         t.option.ALPN,
	}

	// Apply fingerprint if specified
	if t.option.ClientFingerprint != "" {
		utlsConfig, err := vmess.GetUTLSConfig(tlsConfig, t.option.ClientFingerprint)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return vmess.DialTLSWithFingerprint(ctx, tcpConn, utlsConfig)
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

// clientHandshake performs the TQP protocol handshake
func (t *TQP) clientHandshake(conn net.Conn, metadata *C.Metadata) error {
	// Build handshake request
	// Format: Magic(4) + UUID(36) + AddrType(1) + Addr + Port(2)

	uuid := []byte(t.option.UUID)
	if len(uuid) != 36 {
		return errors.New("invalid UUID length")
	}

	// Encode destination
	var addrData []byte
	var addrType byte

	if metadata.DstIP.IsValid() {
		ip := metadata.DstIP
		if ip.Is4() {
			addrType = 0x01 // IPv4
			addrData = ip.AsSlice()
		} else {
			addrType = 0x04 // IPv6
			addrData = ip.AsSlice()
		}
	} else {
		addrType = 0x03 // Domain
		domain := metadata.Host
		addrData = append([]byte{byte(len(domain))}, []byte(domain)...)
	}

	// Build request packet
	portBytes := []byte{byte(metadata.DstPort >> 8), byte(metadata.DstPort & 0xFF)}

	request := make([]byte, 0, 4+36+1+len(addrData)+2)
	request = append(request, tqpMagic...)
	request = append(request, uuid...)
	request = append(request, addrType)
	request = append(request, addrData...)
	request = append(request, portBytes...)

	// Send request
	_, err := conn.Write(request)
	if err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// Read response (2 bytes: status + reserved)
	response := make([]byte, 2)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}

	if response[0] != 0x00 {
		return fmt.Errorf("server rejected connection: status=%d", response[0])
	}

	return nil
}

// ListenPacketContext implements C.ProxyAdapter
func (t *TQP) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	return nil, errors.New("TQP does not support UDP")
}

// SupportUDP returns false as TQP doesn't support UDP
func (t *TQP) SupportUDP() bool {
	return false
}

// ProxyInfo implements C.ProxyAdapter
func (t *TQP) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// NewTQP creates a new TQP adapter
func NewTQP(option TQPOption) (*TQP, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	outbound := &TQP{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.TQP,
			udp:    false,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
	}

	outbound.dialer = proxydialer.NewByNameSingDialer(option.DialerProxy, dialer.NewDialer(outbound.DialOptions()...))

	return outbound, nil
}
