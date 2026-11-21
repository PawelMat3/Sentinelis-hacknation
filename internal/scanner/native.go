package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"asi/internal/ratelimit"
)

// Native is a dependency-free TCP connect scanner with banner grabbing. It is
// slower and less precise than nmap -sV but keeps the system functional on a
// host without nmap and is fully rate limited (connections per second).
type Native struct {
	Timeout     time.Duration
	Parallelism int
}

func (n *Native) Name() string { return "native" }

var wellKnown = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 111: "rpcbind",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 502: "modbus", 554: "rtsp", 587: "submission",
	631: "ipp", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1883: "mqtt", 2049: "nfs", 3000: "http", 3306: "mysql", 3389: "ms-wbt-server",
	5000: "http", 5432: "postgresql", 5601: "http", 5900: "vnc", 6379: "redis", 8000: "http", 8080: "http-proxy", 8081: "http", 8443: "https-alt",
	8888: "http", 9000: "http", 9090: "http", 9100: "jetdirect", 9200: "http", 11211: "memcache", 27017: "mongodb"}

var (
	sshBanner  = regexp.MustCompile(`^SSH-[\d.]+-(\S+)`)
	ftpBanner  = regexp.MustCompile(`^220[ -].*?\(?(vsFTPd|ProFTPD|FileZilla|Pure-FTPd)[ /]?([\w.]*)`)
	smtpBanner = regexp.MustCompile(`^220[ -]\S+ E?SMTP ?(\S+)?`)
)

func (n *Native) Scan(ctx context.Context, targets []string, o Options) ([]HostResult, error) {
	ports, err := ExpandPorts(o.Ports)
	if err != nil {
		return nil, err
	}
	timeout := n.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	par := n.Parallelism
	if par <= 0 {
		par = 64
	}
	lim := ratelimit.New(float64(o.RatePPS), max(1, o.RatePPS/10))
	type job struct {
		hi, port int
		addr     string
	}
	results := make([]HostResult, len(targets))
	var mu sync.Mutex
	jobs := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < par; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for j := range jobs {
				if err := lim.Wait(ctx); err != nil {
					continue
				}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.addr, strconv.Itoa(j.port)))
				if err != nil {
					if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused") {
						mu.Lock()
						results[j.hi].Up = true // RST => host alive
						if results[j.hi].Reason == "" {
							results[j.hi].Reason = "conn-refused"
						}
						mu.Unlock()
					}
					continue
				}
				pr := grab(conn, j.port, timeout)
				conn.Close()
				mu.Lock()
				results[j.hi].Up = true
				results[j.hi].Reason = "syn-ack"
				results[j.hi].Ports = append(results[j.hi].Ports, pr)
				mu.Unlock()
			}
		}()
	}
	for i, t := range targets {
		results[i].Address = t
		addr := t
		if net.ParseIP(t) == nil { // domain: resolve once
			ips, err := net.DefaultResolver.LookupHost(ctx, t)
			if err != nil || len(ips) == 0 {
				continue
			}
			addr = ips[0]
			results[i].Address = addr
			results[i].Hostname = t
			results[i].Target = t
		}
	loop:
		for _, p := range ports {
			select {
			case <-ctx.Done():
				break loop
			case jobs <- job{hi: i, port: p, addr: addr}:
			}
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return results, nil
}

func grab(c net.Conn, port int, timeout time.Duration) PortResult {
	pr := PortResult{Port: port, Proto: "tcp", State: "open", Name: wellKnown[port]}
	if pr.Name == "" {
		pr.Name = "unknown"
	}
	switch port {
	case 80, 443, 8080, 8443, 8000, 8081, 3000, 5000, 9000, 9090, 9200, 5601, 8888:
		// HTTP is fingerprinted later by the prober; just detect TLS.
		if port == 443 || port == 8443 {
			pr.Tunnel = "ssl"
			pr.Name = "https"
		}
		return pr
	}
	c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	k, _ := c.Read(buf)
	b := strings.TrimSpace(strings.ToValidUTF8(string(buf[:k]), ""))
	pr.Banner = b
	switch {
	case sshBanner.MatchString(b):
		pr.Name = "ssh"
		m := sshBanner.FindStringSubmatch(b)
		prod := m[1]
		if strings.HasPrefix(prod, "OpenSSH_") {
			pr.Product, pr.Version = "OpenSSH", strings.ReplaceAll(strings.TrimPrefix(prod, "OpenSSH_"), "_", " ")
		} else {
			pr.Product = prod
		}
	case ftpBanner.MatchString(b):
		m := ftpBanner.FindStringSubmatch(b)
		pr.Name, pr.Product, pr.Version = "ftp", m[1], m[2]
	case smtpBanner.MatchString(b):
		pr.Name = "smtp"
		if m := smtpBanner.FindStringSubmatch(b); len(m) > 1 && m[1] != "" {
			pr.Product = strings.Trim(m[1], "()")
		}
	case strings.HasPrefix(b, "RFB "):
		pr.Name = "vnc"
	case k == 0 && tlsProbe(c.RemoteAddr().String(), timeout):
		pr.Tunnel = "ssl"
	}
	return pr
}

func tlsProbe(addr string, timeout time.Duration) bool {
	d := &net.Dialer{Timeout: timeout}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false
	}
	c.Close()
	return true
}
