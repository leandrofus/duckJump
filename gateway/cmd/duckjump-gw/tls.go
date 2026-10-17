package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// loadTLS loads the certificate for the HTTPS listeners. When neither file
// exists yet it creates a self-signed one (10 years, this host's names and
// addresses), so a fresh install serves HTTPS right away; replace both files
// with a real certificate and restart.
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	_, errC := os.Stat(certFile)
	_, errK := os.Stat(keyFile)
	regen := os.Getenv("DUCKJUMP_REGEN_CERT") == "1"
	if (errors.Is(errC, os.ErrNotExist) && errors.Is(errK, os.ErrNotExist)) || regen {
		if err := selfSigned(certFile, keyFile); err != nil {
			return nil, fmt.Errorf("creating a self-signed certificate: %w", err)
		}
		slog.Warn("created a self-signed TLS certificate; replace it with a real one", "cert", certFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func selfSigned(certFile, keyFile string, extraHosts ...string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	dnsMap := map[string]bool{"localhost": true, "localhost.localdomain": true}
	ipMap := map[string]net.IP{
		"127.0.0.1": net.IPv4(127, 0, 0, 1),
		"::1":       net.IPv6loopback,
	}

	addHost := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		if ip := net.ParseIP(h); ip != nil {
			ipMap[ip.String()] = ip
			return
		}
		dnsMap[h] = true
		if strings.Contains(h, ".") {
			parts := strings.Split(h, ".")
			if parts[0] != "" {
				dnsMap[parts[0]] = true
			}
		}
	}

	if host != "" {
		addHost(host)
	}
	for _, eh := range extraHosts {
		addHost(eh)
	}

	// Read environment variables that may define the gateway host/domain
	for _, envVar := range []string{"DUCKJUMP_HOST", "DUCKJUMP_SERVER_NAME", "DUCKJUMP_FRONTEND_URL", "DUCKJUMP_BIND"} {
		if val := os.Getenv(envVar); val != "" {
			if strings.Contains(val, "://") {
				if u, err := url.Parse(val); err == nil {
					addHost(u.Hostname())
				}
			} else {
				h, _, err := net.SplitHostPort(val)
				if err == nil {
					addHost(h)
				} else {
					addHost(val)
				}
			}
		}
	}

	// Add all local network interface addresses (LAN, Wi-Fi, etc.)
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					if n, ok := a.(*net.IPNet); ok {
						if !n.IP.IsLinkLocalUnicast() && !n.IP.IsMulticast() {
							ipMap[n.IP.String()] = n.IP
						}
					}
				}
			}
		}
	}

	var dnsNames []string
	for name := range dnsMap {
		dnsNames = append(dnsNames, name)
	}
	sort.Strings(dnsNames)

	var ipAddresses []net.IP
	for _, ip := range ipMap {
		ipAddresses = append(ipAddresses, ip)
	}

	cn := host
	if cn == "" {
		cn = "localhost"
	}

	tpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(randomBytes(16)),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"DuckJump (self-signed)"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o750); err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// certFingerprint is how duckjumpd and the gateway pin each other's
// certificates: "SHA256:" + hex of the DER.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

// daemonTLS is the client side of the TLS link to duckjumpd: verified against
// a CA file (DUCKJUMPD_CA), or pinned to a certificate fingerprint
// (DUCKJUMPD_TLS_FINGERPRINT, what `duckjumpd --print-fingerprint` shows).
func daemonTLS(addr, caFile, fingerprint string) (*tls.Config, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13}
	switch {
	case fingerprint != "":
		want := strings.ToLower(strings.TrimSpace(fingerprint))
		conf.InsecureSkipVerify = true // replaced by the pin below
		conf.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || strings.ToLower(certFingerprint(raw[0])) != want {
				return errors.New("duckjumpd certificate does not match DUCKJUMPD_TLS_FINGERPRINT")
			}
			return nil
		}
	case caFile != "":
		pemb, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		conf.RootCAs = x509.NewCertPool()
		if !conf.RootCAs.AppendCertsFromPEM(pemb) {
			return nil, fmt.Errorf("no certificate in %s", caFile)
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		conf.ServerName = host
	default:
		return nil, errors.New("DUCKJUMPD_TLS needs DUCKJUMPD_TLS_FINGERPRINT or DUCKJUMPD_CA")
	}
	return conf, nil
}
