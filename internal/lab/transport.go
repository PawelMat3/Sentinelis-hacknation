package lab

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"
)

// Transport returns a RoundTripper factory compatible with
// fingerprint.Prober.TransportFor that serves simulated sites as they look at
// time t in generation gen. The real fingerprinting code runs unchanged.
func (m *Model) Transport(t time.Time, gen int) func(dialAddr, sni string) http.RoundTripper {
	return func(dialAddr, sni string) http.RoundTripper {
		return &simRT{m: m, t: t, gen: gen, dial: dialAddr, sni: sni}
	}
}

type simRT struct {
	m    *Model
	t    time.Time
	gen  int
	dial string
	sni  string
}

var errRefused = errors.New("connect: connection refused")

func (rt *simRT) RoundTrip(req *http.Request) (*http.Response, error) {
	host, ps, err := net.SplitHostPort(rt.dial)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(ps)
	h, up := rt.m.Probe(host, rt.t, rt.gen)
	if !up {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")}
	}
	var svc *Service
	for i := range h.Services {
		if h.Services[i].Port == port {
			svc = &h.Services[i]
		}
	}
	if svc == nil {
		return nil, errRefused
	}
	if svc.Site == "" {
		return nil, errors.New("malformed HTTP response")
	}
	name := rt.sni
	if name == "" {
		name = h.Hostname
	}
	if rh := req.Host; rh != "" && net.ParseIP(strings.Split(rh, ":")[0]) == nil {
		name = strings.Split(rh, ":")[0]
	}
	if name == "" {
		name = host
	}
	site := rt.m.site(svc.Site, name, svc.SiteVer)
	isTLS := req.URL.Scheme == "https"
	if (site.TLS != "") != isTLS {
		if isTLS {
			return nil, errors.New("tls: first record does not look like a TLS handshake")
		}
		return nil, errors.New("net/http: HTTP/1.x transport connection broken: malformed HTTP response")
	}
	rec := httptest.NewRecorder()
	site.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	if isTLS {
		certName := name
		if site.TLS == CertSelfSigned {
			certName = site.Label // device-style shared certificate (groups by issuer)
		}
		c := rt.m.certs.get(site.TLS, certName)
		ver := uint16(tls.VersionTLS13)
		if site.TLS == CertSelfSigned {
			ver = tls.VersionTLS12
		}
		resp.TLS = &tls.ConnectionState{Version: ver, CipherSuite: tls.TLS_AES_128_GCM_SHA256, HandshakeComplete: true,
			PeerCertificates: []*x509.Certificate{c.Leaf}}
		if ver == tls.VersionTLS12 {
			resp.TLS.CipherSuite = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		}
	}
	return resp, nil
}
