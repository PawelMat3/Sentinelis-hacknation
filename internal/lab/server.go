package lab

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Binding is one listener of the live lab.
type Binding struct {
	Host   int // last octet offset within the lab prefix
	Port   int
	Site   string // web site key, or "" for a raw banner service
	Banner string
	Name   string // hostname (cert/vhost)
	Flap   bool   // only listens during even minutes (unstable host demo)
}

// Layout is the live lab topology (10 hosts, ~20 services).
var Layout = []Binding{
	{Host: 1, Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"},
	{Host: 1, Port: 80, Site: "wordpress", Name: "www.lab.local"},
	{Host: 2, Port: 8080, Site: "jenkins", Name: "ci.lab.local"},
	{Host: 2, Port: 3000, Site: "grafana", Name: "grafana.lab.local"},
	{Host: 3, Port: 80, Site: "staging", Name: "staging.rekrutacja.lab.local"},
	{Host: 3, Port: 22, Banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11\r\n"},
	{Host: 4, Port: 80, Site: "admin", Name: "admin.lab.local"},
	{Host: 4, Port: 8081, Site: "phpmyadmin", Name: "admin.lab.local"},
	{Host: 5, Port: 80, Site: "camera", Name: "cam-01.lab.local"},
	{Host: 6, Port: 443, Site: "owa", Name: "poczta.lab.local"},
	{Host: 6, Port: 25, Banner: "220 poczta.lab.local ESMTP Postfix (Ubuntu)\r\n"},
	{Host: 7, Port: 8080, Site: "actuator", Name: "app.lab.local"},
	{Host: 7, Port: 5000, Site: "flaskdebug", Name: "dev-7.lab.local"},
	{Host: 8, Port: 80, Site: "dirlist", Name: "files.lab.local"},
	{Host: 8, Port: 21, Banner: "220 (vsFTPd 3.0.3)\r\n"},
	{Host: 8, Port: 23, Banner: "\r\nBusyBox v1.31.1 telnetd\r\nlogin: "},
	{Host: 9, Port: 80, Site: "printer", Name: "printer-2.lab.local", Flap: true},
	{Host: 9, Port: 9100, Banner: "", Flap: true},
	{Host: 10, Port: 443, Site: "api", Name: "api-test.lab.local"},
	{Host: 10, Port: 9200, Site: "elastic", Name: "es.lab.local"},
}

// Serve runs the live lab on prefix (e.g. "127.0.1.") until ctx ends.
// portOffset is added to ports < 1024 (for unprivileged runs).
func Serve(ctx context.Context, prefix string, portOffset int, logf func(string, ...any)) error {
	if logf == nil {
		logf = log.Printf
	}
	certs := newCertStore(time.Now())
	type lst struct {
		b    Binding
		addr string
		mu   sync.Mutex
		ln   net.Listener
	}
	var all []*lst
	for _, b := range Layout {
		p := b.Port
		if p < 1024 {
			p += portOffset
		}
		all = append(all, &lst{b: b, addr: net.JoinHostPort(prefix+strconv.Itoa(b.Host), strconv.Itoa(p))})
	}
	start := func(l *lst) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.ln != nil {
			return nil
		}
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			return err
		}
		if l.b.Site != "" {
			site := NewSite(l.b.Site, l.b.Name, 0)
			if site.TLS != "" {
				c := certs.get(site.TLS, l.b.Name)
				ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*c}, MinVersion: tls.VersionTLS12})
			}
			srv := &http.Server{Handler: site, ReadHeaderTimeout: 5 * time.Second}
			go srv.Serve(ln)
		} else {
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						c.SetDeadline(time.Now().Add(5 * time.Second))
						if l.b.Banner != "" {
							c.Write([]byte(l.b.Banner))
						}
						buf := make([]byte, 512)
						c.Read(buf)
					}(c)
				}
			}()
		}
		l.ln = ln
		return nil
	}
	stop := func(l *lst) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.ln != nil {
			l.ln.Close()
			l.ln = nil
		}
	}
	for _, l := range all {
		if l.b.Flap && time.Now().Minute()%2 == 1 {
			continue
		}
		if err := start(l); err != nil {
			return fmt.Errorf("lab listen %s: %w (on Linux use 127.0.1.x loopback; ports <1024 need root or --port-offset)", l.addr, err)
		}
		kind := l.b.Site
		if kind == "" {
			kind = "banner"
		}
		logf("lab: %-22s %-12s %s", l.addr, kind, l.b.Name)
	}
	logf("lab: host %s9 flaps (listening only in even minutes) to demonstrate unstable host handling", prefix)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, l := range all {
				stop(l)
			}
			return nil
		case now := <-t.C:
			for _, l := range all {
				if !l.b.Flap {
					continue
				}
				if now.Minute()%2 == 0 {
					start(l)
				} else {
					stop(l)
				}
			}
		}
	}
}
