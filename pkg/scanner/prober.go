package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Prober sends HTTP(S) probes with a custom Host header.
type Prober struct {
	client  *http.Client
	timeout time.Duration
	headers map[string]string
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
}

var (
	userAgentRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	userAgentMu   sync.Mutex
)

// NewProber creates a prober.
func NewProber(timeout int) *Prober {
	if timeout <= 0 {
		timeout = 5
	}

	return NewProberWithHeaders(timeout, nil)
}

// NewProberWithHeaders creates a prober with extra request headers.
func NewProberWithHeaders(timeout int, headers map[string]string) *Prober {
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
		headers: cloneHeaders(headers),
	}
}

// Probe checks an IP:port with a specific Host header target.
func (p *Prober) Probe(ctx context.Context, ip string, port int, target HostTarget) *CollisionResult {
	start := time.Now()
	result := &CollisionResult{
		IP:        ip,
		Port:      port,
		Host:      target.Host,
		Input:     target.Input,
		Path:      target.Path,
		Timestamp: start,
	}

	for _, scheme := range []string{"http", "https"} {
		requestURL := fmt.Sprintf("%s://%s:%d%s", scheme, ip, port, target.Path)
		req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
		if err != nil {
			continue
		}
		req.Host = target.Host
		userAgent := randomUserAgent()
		req.Header.Set("User-Agent", userAgent)
		for name, value := range p.headers {
			req.Header.Set(name, value)
			if strings.EqualFold(name, "User-Agent") {
				userAgent = value
			}
		}

		resp, err := p.client.Do(req)
		if err != nil {
			result.Error = err.Error()
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*100))
		resp.Body.Close()

		result.StatusCode = resp.StatusCode
		result.ContentLen = len(body)
		result.URL = requestURL
		result.Server = resp.Header.Get("Server")
		result.UserAgent = userAgent
		result.ResponseTime = time.Since(start).Milliseconds()
		result.Title = extractTitle(string(body))
		result.IsValid = resp.StatusCode >= 200 && resp.StatusCode < 400
		result.Error = ""
		return result
	}

	result.ResponseTime = time.Since(start).Milliseconds()
	return result
}

func ParseHostTargets(values []string, defaultPath string) []HostTarget {
	targets := make([]HostTarget, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		target, ok := ParseHostTarget(value, defaultPath)
		if !ok {
			continue
		}
		key := target.Host + "\x00" + target.Path
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets
}

func ParseHostTarget(value string, defaultPath string) (HostTarget, bool) {
	input := strings.TrimSpace(value)
	if input == "" || strings.HasPrefix(input, "#") {
		return HostTarget{}, false
	}

	parseValue := input
	if !strings.Contains(parseValue, "://") {
		parseValue = "http://" + parseValue
	}

	parsed, err := url.Parse(parseValue)
	if err != nil || parsed.Host == "" {
		return HostTarget{}, false
	}

	host := parsed.Host
	path := parsed.EscapedPath()
	if path == "" {
		path = normalizeRequestPath(defaultPath)
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}

	return HostTarget{
		Input: input,
		Host:  host,
		Path:  path,
	}, true
}

func normalizeRequestPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	parseValue := value
	if strings.Contains(parseValue, "://") {
		parsed, err := url.Parse(parseValue)
		if err == nil {
			path := parsed.EscapedPath()
			if path == "" {
				path = "/"
			}
			if parsed.RawQuery != "" {
				path += "?" + parsed.RawQuery
			}
			return path
		}
	}
	if !strings.HasPrefix(parseValue, "/") {
		parseValue = "/" + parseValue
	}
	return parseValue
}

func randomUserAgent() string {
	userAgentMu.Lock()
	defer userAgentMu.Unlock()

	return userAgents[userAgentRand.Intn(len(userAgents))]
}

func extractTitle(html string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
