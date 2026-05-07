package scanner

import "time"

// CollisionResult describes one probe result.
type CollisionResult struct {
	IP           string    `json:"ip"`
	Port         int       `json:"port"`
	Host         string    `json:"host"`
	StatusCode   int       `json:"status_code"`
	Title        string    `json:"title"`
	ContentLen   int       `json:"content_length"`
	Server       string    `json:"server"`
	ResponseTime int64     `json:"response_time_ms"`
	Timestamp    time.Time `json:"timestamp"`
	IsValid      bool      `json:"is_valid"`
	Error        string    `json:"error,omitempty"`
}

// Target groups an IP with candidate host names.
type Target struct {
	IP      string
	Domains []string
}

// Config controls scanner behavior.
type Config struct {
	Threads    int
	QPS        int
	Timeout    int
	Ports      []int
	OutputFile string
}
