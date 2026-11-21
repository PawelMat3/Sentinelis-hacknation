// Package dojo integrates with DefectDojo (API v2): it exports selected
// observations as informational findings through /api/v2/import-scan/ using
// the "Generic Findings Import" format, attaching HTTP/TLS evidence as files,
// and can forward raw nmap XML ("Nmap Scan" parser).
package dojo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	URL             string `json:"url"`
	APIKey          string `json:"api_key"`
	ProductName     string `json:"product_name"`
	ProductTypeName string `json:"product_type_name"`
	EngagementName  string `json:"engagement_name"`
	EngagementID    int    `json:"engagement_id"`
	TestTitle       string `json:"test_title"`
	VerifyTLS       bool   `json:"verify_tls"`
	MinimumSeverity string `json:"minimum_severity"`
}

func (c Config) Valid() error {
	if c.URL == "" || c.APIKey == "" {
		return errors.New("DefectDojo URL and API key are required")
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("invalid DefectDojo URL")
	}
	if c.EngagementID == 0 && (c.ProductName == "" || c.EngagementName == "") {
		return errors.New("set engagement_id or product_name + engagement_name (auto-create)")
	}
	return nil
}

// Masked returns a copy safe to display (API key hidden).
func (c Config) Masked() Config {
	if len(c.APIKey) > 4 {
		c.APIKey = strings.Repeat("•", 8) + c.APIKey[len(c.APIKey)-4:]
	} else if c.APIKey != "" {
		c.APIKey = "••••"
	}
	return c
}

type Endpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Path     string `json:"path,omitempty"`
}

type File struct {
	Title string `json:"title"`
	Data  string `json:"data"` // base64
}

// Finding follows DefectDojo's Generic Findings Import JSON schema.
type Finding struct {
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Severity         string     `json:"severity"`
	Date             string     `json:"date"`
	Mitigation       string     `json:"mitigation,omitempty"`
	Impact           string     `json:"impact,omitempty"`
	References       string     `json:"references,omitempty"`
	Active           bool       `json:"active"`
	Verified         bool       `json:"verified"`
	StaticFinding    bool       `json:"static_finding"`
	DynamicFinding   bool       `json:"dynamic_finding"`
	UniqueIDFromTool string     `json:"unique_id_from_tool"`
	VulnIDFromTool   string     `json:"vuln_id_from_tool,omitempty"`
	Component        string     `json:"component_name,omitempty"`
	ComponentVersion string     `json:"component_version,omitempty"`
	Tags             []string   `json:"tags,omitempty"`
	Endpoints        []Endpoint `json:"endpoints,omitempty"`
	Files            []File     `json:"files,omitempty"`
}

type Report struct {
	Findings []Finding `json:"findings"`
}

// Evidence turns text into an attachable file.
func Evidence(title, text string) File {
	return File{Title: title, Data: base64.StdEncoding.EncodeToString([]byte(text))}
}

// Severity maps ASI priority to DefectDojo severity. Discovery observations
// are informational by default; analysts may raise them.
func Severity(priority string, informationalOnly bool) string {
	if informationalOnly {
		return "Info"
	}
	switch priority {
	case "critical":
		return "High"
	case "high":
		return "Medium"
	case "medium":
		return "Low"
	}
	return "Info"
}

type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !cfg.VerifyTLS {
		tr.TLSClientConfig.InsecureSkipVerify = true // self-hosted lab instances often use internal CAs
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: 60 * time.Second, Transport: tr}}
}

func (c *Client) endpoint(p string) string { return strings.TrimRight(c.cfg.URL, "/") + p }

func (c *Client) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", "Token "+c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		msg := string(b)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return b, fmt.Errorf("DefectDojo HTTP %d: %s", resp.StatusCode, msg)
	}
	return b, nil
}

// Ping verifies URL and API key.
func (c *Client) Ping(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("/api/v2/user_profile/"), nil)
	b, err := c.do(req)
	if err != nil {
		return "", err
	}
	var p struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	json.Unmarshal(b, &p)
	return p.User.Username, nil
}

type ImportResult struct {
	TestID       int    `json:"test"`
	EngagementID int    `json:"engagement_id"`
	ProductID    int    `json:"product_id"`
	Raw          string `json:"-"`
}

func (c *Client) importScan(ctx context.Context, scanType, filename string, data []byte, tags []string) (*ImportResult, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	field := func(k, v string) { mw.WriteField(k, v) }
	field("scan_type", scanType)
	field("scan_date", time.Now().Format("2006-01-02"))
	sev := c.cfg.MinimumSeverity
	if sev == "" {
		sev = "Info"
	}
	field("minimum_severity", sev)
	field("active", "true")
	field("verified", "false")
	field("close_old_findings", "false")
	field("skip_duplicates", "true")
	field("deduplication_on_engagement", "true")
	if c.cfg.TestTitle != "" {
		field("test_title", c.cfg.TestTitle)
	}
	if c.cfg.EngagementID > 0 {
		field("engagement", strconv.Itoa(c.cfg.EngagementID))
	} else {
		field("auto_create_context", "true")
		field("product_name", c.cfg.ProductName)
		field("engagement_name", c.cfg.EngagementName)
		pt := c.cfg.ProductTypeName
		if pt == "" {
			pt = "Attack Surface"
		}
		field("product_type_name", pt)
	}
	for _, t := range tags {
		field("tags", t)
	}
	fw, _ := mw.CreateFormFile("file", filename)
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/api/v2/import-scan/"), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	b, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var r ImportResult
	json.Unmarshal(b, &r)
	r.Raw = string(b)
	return &r, nil
}

// ImportFindings uploads findings as a Generic Findings Import.
func (c *Client) ImportFindings(ctx context.Context, rep Report, tags []string) (*ImportResult, error) {
	if len(rep.Findings) == 0 {
		return nil, errors.New("nothing to export")
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	return c.importScan(ctx, "Generic Findings Import", "asi-findings.json", b, tags)
}

// ImportNmapXML forwards raw nmap XML to DefectDojo's Nmap parser.
func (c *Client) ImportNmapXML(ctx context.Context, xml []byte, tags []string) (*ImportResult, error) {
	return c.importScan(ctx, "Nmap Scan", "nmap.xml", xml, tags)
}
