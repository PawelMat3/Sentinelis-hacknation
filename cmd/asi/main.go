// Command asi - Attack Surface Intelligence.
//
//	asi serve        run API + dashboard + scheduler (default)
//	asi lab          start a local lab of fake services for live demos
//	asi gen-key      print a new base64 master key
//	asi crypto-check show raw encrypted columns and verify decryption
//	asi rotate-key   re-wrap the data key with a new master key
//	asi user add|passwd  manage users from the shell
//	asi healthcheck  probe /healthz (Docker HEALTHCHECK)
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"asi/internal/api"
	"asi/internal/clock"
	"asi/internal/crypto"
	"asi/internal/demo"
	"asi/internal/dojo"
	"asi/internal/lab"
	"asi/internal/orchestrator"
	"asi/internal/scanner"
	"asi/internal/store"
	"asi/internal/vulns"
	"asi/web"
)

var version = "1.0.0"

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(env(k, ""))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envInt(k string, def int) int {
	v, err := strconv.Atoi(env(k, ""))
	if err != nil {
		return def
	}
	return v
}

func main() {
	log.SetFlags(log.LstdFlags)
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "lab":
		err = runLab(args)
	case "gen-key":
		fmt.Println(crypto.EncodeKey(crypto.RandomKey()))
	case "crypto-check":
		err = cryptoCheck(args)
	case "rotate-key":
		err = rotateKey(args)
	case "user":
		err = userCmd(args)
	case "dojo-config":
		err = dojoConfigCmd(args)
	case "healthcheck":
		err = healthcheck()
	case "version":
		fmt.Printf("asi %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\nusage: asi [serve|lab|gen-key|crypto-check|rotate-key|user|dojo-config|healthcheck|version]\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

type common struct {
	dataDir string
	keyFile string
}

func (c *common) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.dataDir, "data", env("ASI_DATA_DIR", "./data"), "data directory (ASI_DATA_DIR)")
	fs.StringVar(&c.keyFile, "key-file", env("ASI_MASTER_KEY_FILE", ""), "master key file (ASI_MASTER_KEY_FILE, default <data>/master.key)")
}

func (c *common) open() (*store.Store, []byte, error) {
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		return nil, nil, err
	}
	kf := c.keyFile
	if kf == "" {
		kf = filepath.Join(c.dataDir, "master.key")
	}
	kek, created, err := crypto.LoadKEK(os.Getenv("ASI_MASTER_KEY"), kf)
	if err != nil {
		return nil, nil, err
	}
	if created {
		log.Printf("security: generated new master key %s (mode 0600). Back it up and keep it outside DB backups - without it the data cannot be decrypted.", kf)
	}
	st, err := store.Open(filepath.Join(c.dataDir, "asi.db"), kek)
	if err != nil {
		return nil, nil, err
	}
	return st, kek, nil
}

func randomPassword() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var c common
	c.flags(fs)
	listen := fs.String("listen", env("ASI_LISTEN", "0.0.0.0:7780"), "listen address (ASI_LISTEN)")
	demoMode := fs.Bool("demo", envBool("ASI_DEMO", false), "seed demo data into an empty database (ASI_DEMO)")
	nmapPath := fs.String("nmap", env("ASI_NMAP_PATH", "nmap"), "nmap binary (ASI_NMAP_PATH)")
	fs.Parse(args)

	st, _, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		return err
	}
	if err := st.SyncBuiltinSignatures(ctx); err != nil {
		return err
	}
	if st.CountUsers(ctx) == 0 {
		pw := env("ASI_ADMIN_PASSWORD", "")
		if pw == "" && *demoMode {
			pw = env("ASI_DEMO_PASSWORD", demo.DefaultPassword)
		}
		generated := pw == ""
		if generated {
			pw = randomPassword()
		}
		admin, _ := st.RoleByName(ctx, "Administracja")
		if _, err := st.CreateUser(ctx, "admin", "Administrator", pw, admin.ID); err != nil {
			return fmt.Errorf("create admin: %w", err)
		}
		if generated {
			p := filepath.Join(c.dataDir, "initial-admin-password.txt")
			os.WriteFile(p, []byte(pw+"\n"), 0o600)
			log.Printf("security: created user 'admin' with generated password (also saved to %s): %s", p, pw)
		} else {
			log.Printf("security: created user 'admin' (password from ASI_ADMIN_PASSWORD/demo)")
		}
	}

	maxRate := envInt("ASI_MAX_RATE", 2000)
	maxTargets := int64(envInt("ASI_MAX_TARGETS", 1<<20))
	model := lab.NewModel(time.Now())
	engines := scanner.Registry{
		"native": &scanner.Native{},
		"sim":    &scanner.Sim{Model: model, Clock: clock.Real{}, CostPerHost: time.Duration(envInt("ASI_SIM_COST_MS", 2)) * time.Millisecond},
	}
	nmapVersion := "niedostępny"
	if p, err := exec.LookPath(*nmapPath); err == nil {
		priv := false
		switch strings.ToLower(env("ASI_NMAP_PRIVILEGED", "auto")) {
		case "true", "1", "yes":
			priv = true
		case "auto":
			priv = runtime.GOOS == "linux" && os.Geteuid() == 0
		}
		nm := &scanner.Nmap{Path: p, Privileged: priv}
		if v, err := nm.Version(); err == nil {
			nmapVersion = v
			if priv {
				nmapVersion += " (raw sockets: SYN scan)"
			} else {
				nmapVersion += " (unprivileged: TCP connect)"
			}
		}
		engines["nmap"] = nm
	} else {
		log.Printf("warning: nmap not found (%v) - jobs using engine 'nmap' will fail; 'native' engine is available", err)
	}

	if *demoMode {
		var n int
		st.DB.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&n)
		if n == 0 {
			log.Printf("demo: seeding demonstration data (simulated 3 days of scans)…")
			t0 := time.Now()
			res, err := demo.Seed(ctx, st, env("ASI_DEMO_PASSWORD", demo.DefaultPassword), log.Printf)
			if err != nil {
				return fmt.Errorf("demo seed: %w", err)
			}
			pwSrc := "default " + demo.DefaultPassword
			if os.Getenv("ASI_DEMO_PASSWORD") != "" {
				pwSrc = "from ASI_DEMO_PASSWORD"
			}
			log.Printf("demo: done in %s - %d runs; demo users %v (password: %s)", time.Since(t0).Round(time.Second), res.Runs, res.Users, pwSrc)
		}
	}

	m := orchestrator.New(st, engines, clock.Real{}, model, orchestrator.Config{MaxRate: maxRate, MaxTargets: maxTargets,
		Tick: time.Duration(envInt("ASI_TICK_SEC", 10)) * time.Second, Logf: log.Printf})
	if !envBool("ASI_NVD_DISABLE", false) {
		m.SetVulnClient(vulns.NewClient(env("ASI_NVD_API_KEY", ""), st)) // CVE lookup for detected versions (NIST NVD)
	}
	if err := m.Start(ctx); err != nil {
		return err
	}
	certFile, keyFile := env("ASI_TLS_CERT", ""), env("ASI_TLS_KEY", "")
	static := web.Static()
	if dir := env("ASI_WEB_DIR", ""); dir != "" { // development: edit the dashboard without rebuilding
		static = os.DirFS(dir)
		log.Printf("web: serving dashboard files from %s (ASI_WEB_DIR, development only)", dir)
	}
	srv := api.New(st, m, static, api.Config{SecureCookie: envBool("ASI_SECURE_COOKIE", certFile != ""), MaxRate: maxRate, MaxTargets: maxTargets,
		Version: version, NmapVersion: nmapVersion, Demo: *demoMode, TrustProxy: envBool("ASI_TRUST_PROXY", false),
		SessionTTL: time.Duration(envInt("ASI_SESSION_HOURS", 12)) * time.Hour})
	hs := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		<-ctx.Done()
		log.Printf("shutting down: pausing active scans (they resume from checkpoint on next start)")
		m.Shutdown(20 * time.Second)
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st.PurgeSessions(context.Background())
			}
		}
	}()
	log.Printf("Sentinelis %s listening on %s (engines: %v, nmap: %s, key %s)", version, *listen, m.Engines(), nmapVersion, st.K.Fingerprint())
	if certFile != "" {
		err = hs.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = hs.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func runLab(args []string) error {
	fs := flag.NewFlagSet("lab", flag.ExitOnError)
	prefix := fs.String("prefix", env("ASI_LAB_PREFIX", "127.0.1."), "IP prefix; hosts are <prefix>1..10")
	offset := fs.Int("port-offset", envInt("ASI_LAB_PORT_OFFSET", 0), "added to ports <1024 (use 8000 when not root)")
	fs.Parse(args)
	if runtime.GOOS == "linux" && os.Geteuid() != 0 && *offset == 0 {
		log.Printf("lab: not root - ports <1024 will fail; use --port-offset 8000 or run as root/in Docker")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("lab: starting fake infrastructure on %s1-10 (Ctrl+C to stop)", *prefix)
	return lab.Serve(ctx, *prefix, *offset, log.Printf)
}

func cryptoCheck(args []string) error {
	fs := flag.NewFlagSet("crypto-check", flag.ExitOnError)
	var c common
	c.flags(fs)
	fs.Parse(args)
	st, _, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	fmt.Printf("Data key fingerprint: %s\n\nEncrypted columns (raw database content):\n", st.K.Fingerprint())
	checks := []struct{ table, col, aad string }{
		{"services", "http_enc", "services.http"}, {"services", "tls_enc", "services.tls"}, {"services", "banner_enc", "services.banner"},
		{"services", "reasons", "services.reasons"}, {"services", "snap_enc", "services.snap"}, {"service_tech", "evidence", "service_tech.evidence"},
		{"annotations", "note_enc", "annotations.note"}, {"annotations", "overrides_enc", "annotations.overrides"},
		{"targets", "note_enc", "targets.note"}, {"changes", "detail_enc", "changes.detail"}, {"settings", "value_enc", "settings.defectdojo"},
	}
	for _, ch := range checks {
		var total, enc int
		st.DB.QueryRow(fmt.Sprintf(`SELECT COUNT(*), SUM(CASE WHEN %s LIKE 'enc:v1:%%' THEN 1 ELSE 0 END) FROM %s WHERE %s!=''`, ch.col, ch.table, ch.col)).Scan(&total, &enc)
		var sample string
		st.DB.QueryRow(fmt.Sprintf(`SELECT %s FROM %s WHERE %s!='' LIMIT 1`, ch.col, ch.table, ch.col)).Scan(&sample)
		status := "OK"
		if total != enc {
			status = "PLAINTEXT FOUND!"
		}
		ok := "-"
		if sample != "" {
			if _, err := st.K.Open(ch.aad, sample); err == nil {
				ok = "decrypts"
			} else {
				ok = "decrypt error"
			}
			if len(sample) > 48 {
				sample = sample[:48] + "…"
			}
		}
		fmt.Printf("  %-14s %-14s %5d/%-5d encrypted  %-16s %s  sample: %s\n", ch.table, ch.col, enc, total, status, ok, sample)
	}
	return nil
}

func rotateKey(args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	var c common
	c.flags(fs)
	newFile := fs.String("new-key-file", "", "file with the new base64 master key (create with: asi gen-key > new.key)")
	fs.Parse(args)
	if *newFile == "" {
		return errors.New("--new-key-file required")
	}
	b, err := os.ReadFile(*newFile)
	if err != nil {
		return err
	}
	newKEK, err := crypto.DecodeKey(string(b))
	if err != nil {
		return err
	}
	st, oldKEK, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.RotateKEK(oldKEK, newKEK); err != nil {
		return err
	}
	fmt.Println("Data key re-wrapped. Replace the old master key with the new one (ASI_MASTER_KEY or key file) before restarting.")
	return nil
}

// dojoConfigCmd configures the DefectDojo integration from the command line
// (headless deployments), e.g.:
//
//	ASI_DOJO_TOKEN=... asi dojo-config --url http://127.0.0.1:8070 --product AGH --engagement "Sentinelis"
//
// The API token is read from --token-file or ASI_DOJO_TOKEN (never from argv)
// and stored encrypted like the token entered in the UI.
func dojoConfigCmd(args []string) error {
	fs := flag.NewFlagSet("dojo-config", flag.ExitOnError)
	var c common
	c.flags(fs)
	u := fs.String("url", "", "DefectDojo base URL, e.g. https://defectdojo.example.org")
	tokenFile := fs.String("token-file", "", "file with the DefectDojo API v2 token (default: $ASI_DOJO_TOKEN)")
	product := fs.String("product", "", "product name (created if missing)")
	productType := fs.String("product-type", "Attack Surface", "product type for auto-created products")
	engagement := fs.String("engagement", "", "engagement name (created if missing)")
	engagementID := fs.Int("engagement-id", 0, "existing engagement id (instead of --product/--engagement)")
	testTitle := fs.String("test-title", "Sentinelis discovery", "title of the DefectDojo test")
	minSev := fs.String("min-severity", "Info", "minimum severity imported by DefectDojo")
	verifyTLS := fs.Bool("verify-tls", true, "verify the DefectDojo TLS certificate")
	check := fs.Bool("test", true, "check the connection before saving")
	fs.Parse(args)
	token := os.Getenv("ASI_DOJO_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	cfg := dojo.Config{URL: *u, APIKey: token, ProductName: *product, ProductTypeName: *productType, EngagementName: *engagement,
		EngagementID: *engagementID, TestTitle: *testTitle, MinimumSeverity: *minSev, VerifyTLS: *verifyTLS}
	if err := cfg.Valid(); err != nil {
		return err
	}
	ctx := context.Background()
	if *check {
		user, err := dojo.New(cfg).Ping(ctx)
		if err != nil {
			return fmt.Errorf("DefectDojo connection test failed: %w", err)
		}
		fmt.Printf("DefectDojo connection OK (API user: %s)\n", user)
	}
	st, _, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SetSetting(ctx, api.DojoSettingKey, cfg); err != nil {
		return err
	}
	st.Audit(ctx, "cli", "update", "settings", 0, "defectdojo "+cfg.URL, "")
	fmt.Printf("saved: %s, product %q, engagement %q (token stored encrypted)\n", cfg.URL, cfg.ProductName, cfg.EngagementName)
	return nil
}

func userCmd(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: asi user add <username> <role name> | asi user passwd <username>   (password read from ASI_PASSWORD or stdin)")
	}
	sub := args[0]
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	var c common
	c.flags(fs)
	fs.Parse(args[1:])
	rest := fs.Args()
	st, _, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	st.EnsureBuiltinRoles(ctx)
	pw := os.Getenv("ASI_PASSWORD")
	if pw == "" {
		fmt.Fprint(os.Stderr, "password: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pw = strings.TrimSpace(line)
	}
	switch sub {
	case "add":
		if len(rest) < 2 {
			return errors.New("usage: asi user add <username> <role name>")
		}
		role, err := st.RoleByName(ctx, strings.Join(rest[1:], " "))
		if err != nil {
			return fmt.Errorf("role %q not found", strings.Join(rest[1:], " "))
		}
		_, err = st.CreateUser(ctx, rest[0], rest[0], pw, role.ID)
		return err
	case "passwd":
		if len(rest) < 1 {
			return errors.New("usage: asi user passwd <username>")
		}
		var id int64
		if err := st.DB.QueryRow(`SELECT id FROM users WHERE username=?`, rest[0]).Scan(&id); err != nil {
			return fmt.Errorf("user %q not found", rest[0])
		}
		return st.UpdateUser(ctx, id, store.UserPatch{Password: &pw})
	}
	return fmt.Errorf("unknown user subcommand %q", sub)
}

func healthcheck() error {
	addr := env("ASI_LISTEN", "0.0.0.0:7780")
	port := addr[strings.LastIndex(addr, ":")+1:]
	scheme := "http"
	if env("ASI_TLS_CERT", "") != "" {
		scheme = "https"
	}
	cl := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // localhost probe only
	resp, err := cl.Get(scheme + "://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
