package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Prober sends HTTP(S) probes with a custom Host header.
type Prober struct {
	client  *http.Client
	timeout time.Duration
}

// NewProber creates a prober.
func NewProber(timeout int) *Prober {
	if timeout <= 0 {
		timeout = 5
	}

	return &Prober{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout: time.Duration(timeout) * time.Second,
				}).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeout: time.Duration(timeout) * time.Second,
	}
}

// Probe checks an IP:port with a specific Host header.
func (p *Prober) Probe(ctx context.Context, ip string, port int, host string) *CollisionResult {
	start := time.Now()
	result := &CollisionResult{
		IP:        ip,
		Port:      port,
		Host:      host,
		Timestamp: start,
	}

	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Host = host

		resp, err := p.client.Do(req)
		if err != nil {
			result.Error = err.Error()
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*100))
		resp.Body.Close()

		result.StatusCode = resp.StatusCode
		result.ContentLen = len(body)
		result.Server = resp.Header.Get("Server")
		result.ResponseTime = time.Since(start).Milliseconds()
		result.Title = extractTitle(string(body))
		result.IsValid = resp.StatusCode >= 200 && resp.StatusCode < 400
		result.Error = ""
		return result
	}

	result.ResponseTime = time.Since(start).Milliseconds()
	return result
}

func extractTitle(html string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
