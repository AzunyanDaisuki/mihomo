package outbound

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/ech/echparser"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/anytls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	shadowtls "github.com/metacubex/mihomo/transport/sing-shadowtls"
	"github.com/metacubex/mihomo/transport/snell"
	v2rayObfs "github.com/metacubex/mihomo/transport/v2ray-plugin"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
)

type Snell struct {
	*Base
	option     *SnellOption
	psk        []byte
	pool       *snell.Pool
	obfsOption *snellObfsOption
	anyTLS     *anytls.Client
	echTLS     *v2rayObfs.Option
	shadowTLS  *shadowtls.ShadowTLSOption
	identity   bool
	version    int
	reuse      bool
}

type SnellOption struct {
	BasicOption
	Name     string         `proxy:"name"`
	Server   string         `proxy:"server"`
	Port     int            `proxy:"port"`
	Psk      string         `proxy:"psk"`
	UDP      bool           `proxy:"udp,omitempty"`
	Version  int            `proxy:"version,omitempty"`
	Reuse    bool           `proxy:"reuse,omitempty"`
	Identity bool           `proxy:"identity,omitempty"`
	ObfsOpts map[string]any `proxy:"obfs-opts,omitempty"`

	ClientFingerprint string `proxy:"client-fingerprint,omitempty"`
}

type snellObfsOption struct {
	Mode              string            `obfs:"mode,omitempty"`
	Host              string            `obfs:"host,omitempty"`
	SNI               string            `obfs:"sni,omitempty"`
	Path              string            `obfs:"path,omitempty"`
	Password          string            `obfs:"password,omitempty"`
	Version           int               `obfs:"version,omitempty"`
	ALPN              []string          `obfs:"alpn,omitempty"`
	TLS               bool              `obfs:"tls,omitempty"`
	ECHConfig         string            `obfs:"ech-config,omitempty"`
	ECHConfigFile     string            `obfs:"ech-config-file,omitempty"`
	CAFile            string            `obfs:"ca-file,omitempty"`
	Insecure          bool              `obfs:"insecure,omitempty"`
	Fingerprint       string            `obfs:"fingerprint,omitempty"`
	ClientFingerprint string            `obfs:"client-fingerprint,omitempty"`
	Certificate       string            `obfs:"certificate,omitempty"`
	PrivateKey        string            `obfs:"private-key,omitempty"`
	Headers           map[string]string `obfs:"headers,omitempty"`
	SkipCertVerify    bool              `obfs:"skip-cert-verify,omitempty"`
}

func isSnellECHTLSMode(mode string) bool {
	return mode == "ech-tls"
}

func snellECHTLSHost(obfsOption *snellObfsOption, server string) string {
	if obfsOption.SNI != "" {
		return obfsOption.SNI
	}
	if obfsOption.Host != "" {
		return obfsOption.Host
	}
	return server
}

func snellECHTLSConfig(obfsOption *snellObfsOption) (*ech.Config, error) {
	if obfsOption.ECHConfig != "" && obfsOption.ECHConfigFile != "" {
		return nil, fmt.Errorf("ech-config and ech-config-file are mutually exclusive")
	}
	if obfsOption.ECHConfig == "" && obfsOption.ECHConfigFile == "" {
		return nil, fmt.Errorf("ech-tls requires ech-config or ech-config-file")
	}

	var list []byte
	var err error
	if obfsOption.ECHConfig != "" {
		list, err = base64.StdEncoding.DecodeString(strings.TrimSpace(obfsOption.ECHConfig))
		if err != nil {
			return nil, fmt.Errorf("base64 decode ech-config failed: %w", err)
		}
	} else {
		path := C.Path.Resolve(obfsOption.ECHConfigFile)
		if !C.Path.IsSafePath(path) {
			return nil, C.Path.ErrNotSafePath(path)
		}
		list, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ech-config-file failed: %w", err)
		}
	}
	if configs, err := echparser.ParseECHConfigList(list); err != nil {
		return nil, fmt.Errorf("parse ech config list failed: %w", err)
	} else if len(configs) == 0 {
		return nil, fmt.Errorf("ech config list is empty")
	}

	return &ech.Config{
		GetEncryptedClientHelloConfigList: func(ctx context.Context, serverName string) ([]byte, error) {
			return list, nil
		},
	}, nil
}

func snellShadowTLSObfsOption(option SnellOption, obfsOption *snellObfsOption) (*shadowtls.ShadowTLSOption, error) {
	if obfsOption.Password == "" {
		return nil, fmt.Errorf("shadow-tls password is empty")
	}

	version := obfsOption.Version
	if version == 0 {
		version = 2
	}
	switch version {
	case 1, 2, 3:
	default:
		return nil, fmt.Errorf("shadow-tls version error: %d", version)
	}

	alpn := obfsOption.ALPN
	if alpn == nil {
		alpn = shadowtls.DefaultALPN
	}
	host := obfsOption.Host
	if host == "" {
		host = "bing.com"
	}

	return &shadowtls.ShadowTLSOption{
		Password:          obfsOption.Password,
		Host:              host,
		Fingerprint:       obfsOption.Fingerprint,
		Certificate:       obfsOption.Certificate,
		PrivateKey:        obfsOption.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		SkipCertVerify:    obfsOption.SkipCertVerify,
		Version:           version,
		ALPN:              alpn,
	}, nil
}

func requiresSnellV4Identity(obfsMode string) bool {
	return obfsMode == "anytls" ||
		isSnellECHTLSMode(obfsMode)
}

func (s *Snell) streamConnContext(ctx context.Context, c net.Conn) (*snell.Snell, error) {
	var err error
	switch s.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, s.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(s.addr)
		c = obfs.NewHTTPObfs(c, s.obfsOption.Host, port)
	case shadowtls.Mode:
		c, err = shadowtls.NewShadowTLS(ctx, c, s.shadowTLS)
		if err != nil {
			return nil, err
		}
	}
	if s.identity && s.version == snell.Version4 {
		return snell.StreamConnWithIdentity(c, s.psk, s.version), nil
	}
	return snell.StreamConn(c, s.psk, s.version), nil
}

// StreamConnContext implements C.ProxyAdapter
func (s *Snell) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c, err := s.streamConnContext(ctx, c)
	if err != nil {
		return nil, err
	}
	err = s.writeHeaderContext(ctx, c, metadata)
	return c, err
}

func (s *Snell) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	if metadata.NetWork == C.UDP {
		err = snell.WriteUDPHeader(c, s.version)
		if err == nil && s.version >= snell.Version4 {
			if sc, ok := c.(*snell.Snell); ok {
				err = sc.ReadReply()
			}
		}
		return
	}
	err = snell.WriteHeaderWithReuse(c, metadata.String(), uint(metadata.DstPort), s.version, s.reuse)
	return
}

// DialContext implements C.ProxyAdapter
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.reuse {
		c, err := s.pool.Get()
		if err != nil {
			return nil, err
		}

		if err = s.writeHeaderContext(ctx, c, metadata); err != nil {
			_ = c.Close()
			return nil, err
		}
		if pc, ok := c.(*snell.PoolConn); ok {
			pc.MarkReusable()
		}
		return NewConn(c, s), err
	}

	c, err := s.dialSnellTransport(ctx)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	return NewConn(c, s), err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err := s.dialSnellTransport(ctx)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	pc := snell.PacketConn(c)
	return NewPacketConn(pc, s), nil
}

func (s *Snell) dialSnellTransport(ctx context.Context) (net.Conn, error) {
	if s.anyTLS != nil {
		return s.anyTLS.CreateRawStream(ctx)
	}
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	if s.echTLS != nil {
		obfsConn, err := v2rayObfs.NewV2rayObfs(ctx, c, s.echTLS)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		c = obfsConn
	}
	return c, nil
}

// SupportUOT implements C.ProxyAdapter
func (s *Snell) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (s *Snell) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func NewSnell(option SnellOption) (*Snell, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	psk := []byte(option.Psk)

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	obfsOption := &snellObfsOption{}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}
	var shadowTLSOption *shadowtls.ShadowTLSOption
	switch obfsOption.Mode {
	case "tls", "http", "anytls", "ech-tls", "":
	case shadowtls.Mode:
		var err error
		shadowTLSOption, err = snellShadowTLSObfsOption(option, obfsOption)
		if err != nil {
			return nil, fmt.Errorf("snell %s initialize shadow-tls-plugin error: %w", addr, err)
		}
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}
	if obfsOption.Host == "" && (obfsOption.Mode == "tls" || obfsOption.Mode == "http") {
		obfsOption.Host = "bing.com"
	}
	if isSnellECHTLSMode(obfsOption.Mode) {
		if obfsOption.Path == "" {
			return nil, fmt.Errorf("snell %s ech-tls path is empty", addr)
		}
		obfsOption.TLS = true
		obfsOption.Host = snellECHTLSHost(obfsOption, option.Server)
		obfsOption.SkipCertVerify = obfsOption.SkipCertVerify || obfsOption.Insecure
	}

	if obfsOption.Mode == "anytls" && obfsOption.Password == "" {
		return nil, fmt.Errorf("snell %s anytls password is empty", addr)
	}
	if isSnellECHTLSMode(obfsOption.Mode) && obfsOption.CAFile != "" && obfsOption.SkipCertVerify {
		return nil, fmt.Errorf("snell %s ca-file and insecure/skip-cert-verify are mutually exclusive", addr)
	}

	// backward compatible
	if option.Version == 0 {
		if requiresSnellV4Identity(obfsOption.Mode) {
			option.Version = snell.Version4
		} else {
			option.Version = snell.DefaultSnellVersion
		}
	}
	if requiresSnellV4Identity(obfsOption.Mode) && option.Version == snell.Version4 {
		option.Identity = true
	}
	if option.Version == snell.Version5 {
		// Snell v5 servers are backward-compatible with v4 clients.
		option.Version = snell.Version4
	}
	reuse := option.Version == snell.Version2 || (option.Version == snell.Version4 && option.Reuse)
	switch option.Version {
	case snell.Version1, snell.Version2:
		if option.UDP {
			return nil, fmt.Errorf("snell version %d not support UDP", option.Version)
		}
	case snell.Version3, snell.Version4:
	default:
		return nil, fmt.Errorf("snell version error: %d", option.Version)
	}

	s := &Snell{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Snell,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:     &option,
		psk:        psk,
		obfsOption: obfsOption,
		identity:   option.Identity,
		version:    option.Version,
		reuse:      reuse,
		shadowTLS:  shadowTLSOption,
	}
	s.dialer = option.NewDialer(s.DialOptions())
	if obfsOption.Mode == "anytls" {
		singDialer := proxydialer.NewSingDialer(s.dialer)
		// Carry the uTLS client-fingerprint from obfs-opts into the AnyTLS outer
		// handshake, matching the ech-tls leg (both are obfs-opts modes). An empty
		// value still falls back to the global fingerprint inside GetFingerprint.
		tlsConfig := &vmess.TLSConfig{
			Host:              obfsOption.Host,
			SkipCertVerify:    obfsOption.SkipCertVerify,
			ClientFingerprint: obfsOption.ClientFingerprint,
		}
		if tlsConfig.Host == "" {
			tlsConfig.Host = option.Server
		}
		s.anyTLS = anytls.NewClient(context.TODO(), anytls.ClientConfig{
			Password:                 obfsOption.Password,
			Server:                   M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
			Dialer:                   singDialer,
			TLSConfig:                tlsConfig,
			IdleSessionCheckInterval: 30 * time.Second,
			IdleSessionTimeout:       30 * time.Second,
		})
	}
	if isSnellECHTLSMode(obfsOption.Mode) {
		echConfig, err := snellECHTLSConfig(obfsOption)
		if err != nil {
			return nil, err
		}
		s.echTLS = &v2rayObfs.Option{
			Host:              obfsOption.Host,
			Port:              strconv.Itoa(option.Port),
			Path:              obfsOption.Path,
			Headers:           obfsOption.Headers,
			TLS:               obfsOption.TLS,
			ECHConfig:         echConfig,
			SkipCertVerify:    obfsOption.SkipCertVerify,
			CAFile:            obfsOption.CAFile,
			ClientFingerprint: obfsOption.ClientFingerprint,
			Fingerprint:       obfsOption.Fingerprint,
			Certificate:       obfsOption.Certificate,
			PrivateKey:        obfsOption.PrivateKey,
		}
	}

	if s.reuse {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			c, err := s.dialSnellTransport(ctx)
			if err != nil {
				return nil, err
			}

			return s.streamConnContext(ctx, c)
		})
	}
	return s, nil
}

func (s *Snell) Close() error {
	if s.anyTLS != nil {
		return s.anyTLS.Close()
	}
	return s.Base.Close()
}
