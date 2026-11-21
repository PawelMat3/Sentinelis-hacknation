package lab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// Cert kinds used by simulated sites.
const (
	CertValid      = "valid"
	CertSelfSigned = "self-signed"
	CertExpired    = "expired"
	CertExpiring   = "expiring"
)

type certStore struct {
	mu    sync.Mutex
	base  time.Time
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	cache map[string]*tls.Certificate
}

func newCertStore(base time.Time) *certStore {
	cs := &certStore{base: base, cache: map[string]*tls.Certificate{}}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AGH Lab Internal CA", Organization: []string{"Laboratorium ASI"}},
		NotBefore:             base.AddDate(-2, 0, 0),
		NotAfter:              base.AddDate(8, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cs.ca, _ = x509.ParseCertificate(der)
	cs.caKey = key
	return cs
}

// get returns (cached) a certificate of the given kind for name.
func (cs *certStore) get(kind, name string) *tls.Certificate {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	k := kind + "|" + name
	if c, ok := cs.cache[k]; ok {
		return c
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Laboratorium ASI"}},
		NotBefore:    cs.base.AddDate(0, -6, 0),
		NotAfter:     cs.base.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	parent, signer := cs.ca, cs.caKey
	switch kind {
	case CertSelfSigned:
		tmpl.Subject = pkix.Name{CommonName: name, Organization: []string{"Embedded Device"}}
		parent, signer = tmpl, key
	case CertExpired:
		tmpl.NotBefore = cs.base.AddDate(-2, 0, 0)
		tmpl.NotAfter = cs.base.AddDate(0, -2, 0)
	case CertExpiring:
		tmpl.NotAfter = cs.base.AddDate(0, 0, 9)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	cs.cache[k] = c
	return c
}
