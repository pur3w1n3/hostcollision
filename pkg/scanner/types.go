package scanner

import "time"

// CollisionResult describes one probe result.
type CollisionResult struct {
	IP           string    `json:"ip"`
	Port         int       `json:"port"`
	Host         string    `json:"host"`
	Input        string    `json:"input"`
	Path         string    `json:"path"`
	URL          string    `json:"url"`
	StatusCode   int       `json:"status_code"`
	Title        string    `json:"title"`
	ContentLen   int       `json:"content_length"`
	Server       string    `json:"server"`
	UserAgent    string    `json:"user_agent"`
	ResponseTime int64     `json:"response_time_ms"`
	Timestamp    time.Time `json:"timestamp"`
	IsValid      bool      `json:"is_valid"`
	Error        string    `json:"error,omitempty"`
}

// HostTarget is one Host header candidate and optional request path.
type HostTarget struct {
	Input string
	Host  string
	Path  string
}

// Config controls scanner behavior.
type Config struct {
	Threads    int
	QPS        int
	Timeout    int
	Ports      []int
	Path       string
	Headers    map[string]string
	OutputFile string
}
