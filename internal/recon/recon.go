// Package recon expands a domain into subdomains using passive sources only:
// Certificate Transparency logs (crt.sh) + DNS resolution. No packet is sent
// to the target during this step.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type Subdomain struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

// CRTURL can be overridden in tests.
var CRTURL = "https://crt.sh/"

// Subdomains queries crt.sh for *.domain, keeps names that resolve in DNS and
// returns at most limit of them (sorted). The domain itself is always first
// when it resolves.
func Subdomains(ctx context.Context, domain string, limit int) ([]Subdomain, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	cl := &http.Client{Timeout: 45 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, CRTURL+"?q="+url.QueryEscape("%."+domain)+"&output=json", nil)
	req.Header.Set("User-Agent", "Sentinelis/1.0")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh HTTP %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh: unexpected response")
	}
	seen := map[string]bool{domain: true}
	names := []string{domain}
	for _, r := range rows {
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n)), "*.")
			if n == "" || seen[n] || !strings.HasSuffix(n, "."+domain) || strings.ContainsAny(n, " @*") {
				continue
			}
			seen[n] = true
			names = append(names, n)
		}
	}
	// resolve in parallel; keep only names that exist today
	type res struct {
		i   int
		ips []string
	}
	out := make([][]string, len(names))
	ch := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 24; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
				ips, err := net.DefaultResolver.LookupHost(rctx, names[i])
				cancel()
				if err == nil {
					out[i] = ips
				}
			}
		}()
	}
	for i := range names {
		ch <- i
	}
	close(ch)
	wg.Wait()
	var subs []Subdomain
	for i, n := range names {
		if len(out[i]) > 0 {
			sort.Strings(out[i])
			subs = append(subs, Subdomain{Name: n, IPs: out[i]})
		}
	}
	if len(subs) > 1 {
		rest := subs[1:]
		if subs[0].Name != domain {
			rest = subs
		}
		sort.Slice(rest, func(a, b int) bool { return rest[a].Name < rest[b].Name })
	}
	if limit > 0 && len(subs) > limit {
		subs = subs[:limit]
	}
	return subs, nil
}
