package gui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hostcollision/pkg/scanner"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scanRequest struct {
	IPs     string `json:"ips"`
	Hosts   string `json:"hosts"`
	Path    string `json:"path"`
	Headers string `json:"headers"`
	Threads int    `json:"threads"`
	QPS     int    `json:"qps"`
	Timeout int    `json:"timeout"`
	Ports   string `json:"ports"`
}

type scanStartResponse struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Total      int    `json:"total"`
	ResultFile string `json:"result_file"`
}

type scanStatusResponse struct {
	ID               string                     `json:"id"`
	Status           string                     `json:"status"`
	Error            string                     `json:"error,omitempty"`
	Total            int                        `json:"total"`
	Count            int                        `json:"count"`
	Skipped          int                        `json:"skipped"`
	Results          []*scanner.CollisionResult `json:"results"`
	ResultOffset     int                        `json:"result_offset"`
	NextResultOffset int                        `json:"next_result_offset"`
	ResultCount      int                        `json:"result_count"`
	Logs             []string                   `json:"logs"`
	LogOffset        int                        `json:"log_offset"`
	NextLogOffset    int                        `json:"next_log_offset"`
	LogCount         int                        `json:"log_count"`
	ResultFile       string                     `json:"result_file"`
	StartedAt        time.Time                  `json:"started_at"`
	FinishedAt       *time.Time                 `json:"finished_at,omitempty"`
}

type scanManager struct {
	mu         sync.Mutex
	sessions   map[string]*scanSession
	timeoutLog *guiFileLog
}

type scanSession struct {
	mu           sync.Mutex
	id           string
	status       string
	err          string
	total        int
	skipped      int
	results      []*scanner.CollisionResult
	logs         []string
	resultFile   string
	resultWriter *scanner.ResultWriter
	subscribers  map[chan scanEvent]struct{}
	startedAt    time.Time
	finishedAt   *time.Time
}

type scanEvent struct {
	Type        string                   `json:"type"`
	Status      string                   `json:"status,omitempty"`
	Error       string                   `json:"error,omitempty"`
	Total       int                      `json:"total,omitempty"`
	Count       int                      `json:"count,omitempty"`
	Skipped     int                      `json:"skipped,omitempty"`
	ResultFile  string                   `json:"result_file,omitempty"`
	Result      *scanner.CollisionResult `json:"result,omitempty"`
	ResultIndex int                      `json:"result_index"`
	Log         string                   `json:"log,omitempty"`
	LogIndex    int                      `json:"log_index"`
}

const (
	defaultStatusLimit = 100
	maxStatusLimit     = 500
	maxScanSessions    = 20
	scanSessionTTL     = 30 * time.Minute
)

// StartNativeGUI starts the cross-platform browser GUI.
func StartNativeGUI() {
	timeoutLog, err := newGUIFileLog("timeout.log")
	if err != nil {
		fmt.Printf("[!] Could not open GUI timeout log file: %v\n", err)
	}
	defer timeoutLog.Close()

	manager := newScanManager(timeoutLog)
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/scan", manager.serveScan)
	mux.HandleFunc("/scan/status", manager.serveScanStatus)
	mux.HandleFunc("/scan/events", manager.serveScanEvents)

	server := &http.Server{
		Addr:              "127.0.0.1:0",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatalf("start GUI listener: %v", err)
	}

	url := "http://" + listener.Addr().String()
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("start GUI server: %v", err)
		}
	}()

	fmt.Printf("[*] GUI is running at %s\n", url)
	if err := openBrowser(url); err != nil {
		fmt.Printf("[!] Could not open browser automatically: %v\n", err)
		fmt.Printf("[*] Open this URL manually: %s\n", url)
	}

	select {}
}

func newScanManager(timeoutLog *guiFileLog) *scanManager {
	return &scanManager{
		sessions:   make(map[string]*scanSession),
		timeoutLog: timeoutLog,
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (m *scanManager) serveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}

	parsedHeaders, err := scanner.ParseHeaders(parseLines(req.Headers))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	config := &scanner.Config{
		Threads: req.Threads,
		QPS:     req.QPS,
		Timeout: req.Timeout,
		Ports:   scanner.ParsePorts(req.Ports),
		Path:    req.Path,
		Headers: parsedHeaders,
	}
	scn := scanner.NewScanner(config)

	ips, err := scanner.ExpandIPInputs(parseLines(req.IPs))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hosts := parseLines(req.Hosts)
	targets := scanner.ParseHostTargets(hosts, req.Path)
	if len(ips) == 0 || len(targets) == 0 {
		http.Error(w, "at least one IP and one host header/domain are required", http.StatusBadRequest)
		return
	}

	session := m.newSession(len(ips) * len(targets) * len(config.Ports))
	if err := session.openResultWriter(); err != nil {
		session.addLog("[!] Could not open GUI result CSV: " + err.Error())
	} else {
		session.addLog("[*] Result CSV: " + session.resultFile)
	}
	scn.SetStoreResults(false)
	scn.SetResultCallback(session.addResult)
	scn.SetLogCallback(session.addLog)
	scn.SetTimeoutCallback(func(result *scanner.CollisionResult) {
		line := scanner.FormatTimeoutResult(result)
		if err := m.writeTimeoutLog(line); err != nil {
			session.addLog("[!] Could not write timeout log: " + err.Error())
		}
	})
	session.addLog("[*] Timeout/no-status log: timeout.log")

	go session.run(scn, ips, targets, len(config.Ports))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(scanStartResponse{
		ID:         session.id,
		Status:     session.status,
		Total:      session.total,
		ResultFile: session.resultFile,
	})
}

func (m *scanManager) serveScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}

	session := m.getSession(id)
	if session == nil {
		http.Error(w, "scan session not found", http.StatusNotFound)
		return
	}

	resultOffset := parseNonNegativeInt(r.URL.Query().Get("result_offset"), 0)
	resultLimit := parseBoundedPositiveInt(r.URL.Query().Get("result_limit"), defaultStatusLimit, maxStatusLimit)
	logOffset := parseNonNegativeInt(r.URL.Query().Get("log_offset"), 0)
	logLimit := parseBoundedPositiveInt(r.URL.Query().Get("log_limit"), defaultStatusLimit, maxStatusLimit)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(session.snapshot(resultOffset, resultLimit, logOffset, logLimit))
}

func (m *scanManager) serveScanEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}

	session := m.getSession(id)
	if session == nil {
		http.Error(w, "scan session not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	events := session.subscribe()
	defer session.unsubscribe(events)

	for _, event := range session.initialEvents() {
		if err := writeScanEvent(w, event); err != nil {
			return
		}
		flusher.Flush()
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-events:
			if err := writeScanEvent(w, event); err != nil {
				return
			}
			flusher.Flush()
			if event.Type == "finished" || event.Type == "failed" {
				return
			}
		}
	}
}

func (m *scanManager) newSession(total int) *scanSession {
	now := time.Now()
	session := &scanSession{
		id:          newSessionID(),
		status:      "running",
		total:       total,
		results:     make([]*scanner.CollisionResult, 0),
		logs:        make([]string, 0),
		subscribers: make(map[chan scanEvent]struct{}),
		startedAt:   now,
	}

	m.mu.Lock()
	m.pruneLocked(now)
	m.sessions[session.id] = session
	m.mu.Unlock()
	return session
}

func (m *scanManager) getSession(id string) *scanSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.sessions[id]
}

func (m *scanManager) writeTimeoutLog(line string) error {
	if m == nil || m.timeoutLog == nil {
		return nil
	}
	return m.timeoutLog.Write(line)
}

func (m *scanManager) pruneLocked(now time.Time) {
	for id, session := range m.sessions {
		if session.expired(now) {
			delete(m.sessions, id)
		}
	}

	for len(m.sessions) >= maxScanSessions {
		oldestID := ""
		var oldestFinishedAt time.Time
		for id, session := range m.sessions {
			finishedAt, ok := session.finishedTime()
			if !ok {
				continue
			}
			if oldestID == "" || finishedAt.Before(oldestFinishedAt) {
				oldestID = id
				oldestFinishedAt = finishedAt
			}
		}
		if oldestID == "" {
			return
		}
		delete(m.sessions, oldestID)
	}
}

func (s *scanSession) run(scn *scanner.Scanner, ips []string, targets []scanner.HostTarget, portCount int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.finish("failed", fmt.Sprintf("%v", recovered), scn.GetSkippedCount())
		}
	}()

	s.addLog(fmt.Sprintf("[*] GUI scan started | IPs: %d | Hosts: %d | Ports: %d", len(ips), len(targets), portCount))
	scn.ScanHostTargets(ips, targets)
	s.addLog(fmt.Sprintf("[*] GUI scan finished, %d results, %d timeout/no-status, %d skipped", scn.GetResultCount(), scn.GetTimeoutCount(), scn.GetSkippedCount()))
	s.finish("finished", "", scn.GetSkippedCount())
}

func (s *scanSession) addResult(result *scanner.CollisionResult) {
	if err := s.writeResult(result); err != nil {
		s.addLog("[!] Could not write result CSV: " + err.Error())
	}

	s.mu.Lock()
	index := len(s.results)
	s.results = append(s.results, result)
	event := s.stateEventLocked("result")
	event.Result = result
	event.ResultIndex = index
	s.broadcastLocked(event)
	s.mu.Unlock()
}

func (s *scanSession) addLog(line string) {
	s.mu.Lock()
	index := len(s.logs)
	s.logs = append(s.logs, line)
	event := s.stateEventLocked("log")
	event.Log = line
	event.LogIndex = index
	s.broadcastLocked(event)
	s.mu.Unlock()
}

func (s *scanSession) finish(status string, err string, skipped int) {
	now := time.Now()

	s.mu.Lock()
	s.status = status
	s.err = err
	s.skipped = skipped
	s.finishedAt = &now
	s.broadcastLocked(s.stateEventLocked(status))
	resultWriter := s.resultWriter
	s.resultWriter = nil
	s.mu.Unlock()

	if resultWriter != nil {
		if closeErr := resultWriter.Close(); closeErr != nil {
			s.addLog("[!] Could not close result CSV: " + closeErr.Error())
		}
	}
}

func (s *scanSession) openResultWriter() error {
	filename := "hostcollision-gui-" + s.id + ".csv"
	writer, err := scanner.NewResultWriter(filename)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.resultFile = filename
	s.resultWriter = writer
	s.mu.Unlock()
	return nil
}

func (s *scanSession) writeResult(result *scanner.CollisionResult) error {
	s.mu.Lock()
	writer := s.resultWriter
	s.mu.Unlock()

	if writer == nil {
		return nil
	}
	return writer.Write(result)
}

func (s *scanSession) subscribe() chan scanEvent {
	events := make(chan scanEvent, 4096)
	s.mu.Lock()
	s.subscribers[events] = struct{}{}
	s.mu.Unlock()
	return events
}

func (s *scanSession) unsubscribe(events chan scanEvent) {
	s.mu.Lock()
	delete(s.subscribers, events)
	close(events)
	s.mu.Unlock()
}

func (s *scanSession) initialEvents() []scanEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	events := make([]scanEvent, 0, 1+len(s.results)+len(s.logs)+1)
	events = append(events, s.stateEventLocked("snapshot"))
	for index, result := range s.results {
		event := s.stateEventLocked("result")
		event.Result = result
		event.ResultIndex = index
		events = append(events, event)
	}
	for index, logLine := range s.logs {
		event := s.stateEventLocked("log")
		event.Log = logLine
		event.LogIndex = index
		events = append(events, event)
	}
	if s.status == "finished" || s.status == "failed" {
		events = append(events, s.stateEventLocked(s.status))
	}
	return events
}

func (s *scanSession) stateEventLocked(eventType string) scanEvent {
	return scanEvent{
		Type:       eventType,
		Status:     s.status,
		Error:      s.err,
		Total:      s.total,
		Count:      len(s.results),
		Skipped:    s.skipped,
		ResultFile: s.resultFile,
	}
}

func (s *scanSession) broadcastLocked(event scanEvent) {
	for events := range s.subscribers {
		select {
		case events <- event:
		default:
		}
	}
}

func (s *scanSession) expired(now time.Time) bool {
	finishedAt, ok := s.finishedTime()
	return ok && now.Sub(finishedAt) > scanSessionTTL
}

func (s *scanSession) finishedTime() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.finishedAt == nil {
		return time.Time{}, false
	}
	return *s.finishedAt, true
}

func (s *scanSession) snapshot(resultOffset, resultLimit, logOffset, logLimit int) scanStatusResponse {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, nextResultOffset := sliceResults(s.results, resultOffset, resultLimit)
	logs, nextLogOffset := sliceStrings(s.logs, logOffset, logLimit)

	return scanStatusResponse{
		ID:               s.id,
		Status:           s.status,
		Error:            s.err,
		Total:            s.total,
		Count:            len(s.results),
		Skipped:          s.skipped,
		Results:          results,
		ResultOffset:     resultOffset,
		NextResultOffset: nextResultOffset,
		ResultCount:      len(s.results),
		Logs:             logs,
		LogOffset:        logOffset,
		NextLogOffset:    nextLogOffset,
		LogCount:         len(s.logs),
		ResultFile:       s.resultFile,
		StartedAt:        s.startedAt,
		FinishedAt:       s.finishedAt,
	}
}

func sliceResults(results []*scanner.CollisionResult, offset, limit int) ([]*scanner.CollisionResult, int) {
	if offset > len(results) {
		offset = len(results)
	}
	end := offset + limit
	if end > len(results) {
		end = len(results)
	}
	page := make([]*scanner.CollisionResult, end-offset)
	copy(page, results[offset:end])
	return page, end
}

func sliceStrings(values []string, offset, limit int) ([]string, int) {
	if offset > len(values) {
		offset = len(values)
	}
	end := offset + limit
	if end > len(values) {
		end = len(values)
	}
	page := make([]string, end-offset)
	copy(page, values[offset:end])
	return page, end
}

func writeScanEvent(w http.ResponseWriter, event scanEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
	return err
}

func parseNonNegativeInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func parseBoundedPositiveInt(value string, fallback int, maxValue int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	if parsed > maxValue {
		return maxValue
	}
	return parsed
}

func newSessionID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

func parseLines(text string) []string {
	var lines []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

func openBrowser(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", url)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", url)
	}

	return cmd.Start()
}

type guiFileLog struct {
	mu   sync.Mutex
	file *os.File
}

func newGUIFileLog(filename string) (*guiFileLog, error) {
	if filename == "" {
		return &guiFileLog{}, nil
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &guiFileLog{file: file}, nil
}

func (w *guiFileLog) Write(message string) error {
	if w == nil || w.file == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := fmt.Fprintf(w.file, "%s %s\n", time.Now().Format(time.RFC3339), message)
	return err
}

func (w *guiFileLog) Close() error {
	if w == nil || w.file == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	err := w.file.Close()
	w.file = nil
	return err
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Host Collision</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fa;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #65748b;
      --line: #d9e2ec;
      --accent: #0f766e;
      --accent-strong: #0b5f59;
      --warn: #b45309;
      --bad: #b91c1c;
      --good: #047857;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      letter-spacing: 0;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 20px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 650;
    }
    .brand {
      display: flex;
      align-items: baseline;
      gap: 10px;
      flex-wrap: wrap;
    }
    .task-id {
      color: var(--muted);
      font-size: 13px;
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    }
    .status {
      min-width: 190px;
      text-align: right;
      color: var(--muted);
      font-size: 14px;
    }
    main {
      display: grid;
      grid-template-columns: minmax(280px, 340px) minmax(0, 1fr);
      min-height: calc(100vh - 57px);
    }
    aside {
      border-right: 1px solid var(--line);
      background: var(--panel);
      padding: 18px;
      overflow: auto;
    }
    section {
      padding: 18px;
      overflow: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .field {
      display: grid;
      gap: 7px;
      margin-bottom: 14px;
    }
    .field-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }
    .field-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    label {
      font-size: 13px;
      font-weight: 650;
      color: #334e68;
    }
    textarea,
    input,
    select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      color: var(--text);
      background: #fff;
      outline: none;
    }
    textarea {
      min-height: 112px;
      resize: vertical;
      line-height: 1.45;
    }
    textarea:focus,
    input:focus,
    select:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.12);
    }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 16px;
    }
    button {
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 13px;
      background: #fff;
      color: var(--text);
      font: inherit;
      font-weight: 650;
      cursor: pointer;
    }
    button.small {
      min-height: 30px;
      padding: 0 10px;
      font-size: 12px;
    }
    button.primary {
      flex: 1;
      border-color: var(--accent);
      background: var(--accent);
      color: #fff;
    }
    button.primary:hover { background: var(--accent-strong); }
    button:disabled {
      opacity: 0.62;
      cursor: not-allowed;
    }
    .toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .summary {
      color: var(--muted);
      font-size: 14px;
    }
    .result-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .page-label {
      min-width: 76px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
    }
    .table-wrap {
      width: 100%;
      flex: 1;
      min-height: 0;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 920px;
    }
    th,
    td {
      padding: 10px 11px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      font-size: 13px;
      vertical-align: top;
    }
    th {
      position: sticky;
      top: 0;
      background: #eef3f8;
      color: #334e68;
      font-weight: 700;
      z-index: 1;
      user-select: none;
    }
    th[data-sort] {
      cursor: pointer;
      white-space: nowrap;
    }
    th[data-sort]::after {
      content: "  ";
      color: var(--muted);
      font-size: 11px;
    }
    th[data-sort].sort-asc::after {
      content: " asc";
    }
    th[data-sort].sort-desc::after {
      content: " desc";
    }
    tr:last-child td { border-bottom: 0; }
    .valid { color: var(--good); font-weight: 700; }
    .invalid { color: var(--bad); font-weight: 700; }
    .empty {
      display: block;
      min-height: 0;
      padding: 9px 11px;
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--muted);
      background: var(--panel);
    }
    .error {
      color: var(--warn);
      overflow-wrap: anywhere;
    }
    .log-panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      min-height: 132px;
      max-height: 190px;
      display: flex;
      flex-direction: column;
    }
    .log-head {
      padding: 8px 11px;
      border-bottom: 1px solid var(--line);
      color: #334e68;
      font-size: 13px;
      font-weight: 700;
    }
    .logs {
      margin: 0;
      padding: 9px 11px;
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      color: var(--muted);
      font: 12px/1.45 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    }
    .file-input {
      position: absolute;
      inline-size: 1px;
      block-size: 1px;
      opacity: 0;
      pointer-events: none;
    }
    @media (max-width: 860px) {
      header {
        align-items: flex-start;
        flex-direction: column;
      }
      .status {
        min-width: 0;
        text-align: left;
      }
      main {
        grid-template-columns: 1fr;
      }
      aside {
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }
      .grid {
        grid-template-columns: 1fr;
      }
      .field-head {
        align-items: flex-start;
        flex-direction: column;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>Host Collision</h1>
      <span id="task-id" class="task-id">No task</span>
    </div>
    <div id="status" class="status">Ready</div>
  </header>
  <main>
    <aside>
      <div class="field">
        <div class="field-head">
          <label for="ips">Target IPs</label>
          <div class="field-actions">
            <button id="load-ips" class="small" type="button">Upload</button>
            <button id="clear-ips" class="small" type="button">Clear</button>
          </div>
        </div>
        <input id="ips-file" class="file-input" type="file" accept=".txt,.csv,text/plain,text/csv">
        <textarea id="ips" spellcheck="false">192.168.1.1
10.0.0.1
8.8.8.8</textarea>
      </div>
      <div class="field">
        <div class="field-head">
          <label for="hosts">Host Headers / Domains / URLs</label>
          <div class="field-actions">
            <button id="load-hosts" class="small" type="button">Upload</button>
            <button id="clear-hosts" class="small" type="button">Clear</button>
          </div>
        </div>
        <input id="hosts-file" class="file-input" type="file" accept=".txt,.csv,text/plain,text/csv">
        <textarea id="hosts" spellcheck="false">example.com
example.com/admin
https://test.com/login?a=1
test.com
demo.com</textarea>
      </div>
      <div class="field">
        <label for="path">Optional URL Path</label>
        <input id="path" placeholder="/login?a=1 or https://example.com/login?a=1">
      </div>
      <div class="field">
        <label for="headers">Headers</label>
        <textarea id="headers" spellcheck="false" placeholder="User-Agent: custom&#10;X-Forwarded-For: 127.0.0.1"></textarea>
      </div>
      <div class="grid">
        <div class="field">
          <label for="threads">Threads</label>
          <input id="threads" type="number" min="1" max="512" value="20">
        </div>
        <div class="field">
          <label for="qps">QPS</label>
          <input id="qps" type="number" min="1" max="10000" value="30">
        </div>
        <div class="field">
          <label for="timeout">Timeout</label>
          <input id="timeout" type="number" min="1" max="120" value="5">
        </div>
        <div class="field">
          <label for="ports">Ports</label>
          <input id="ports" value="80,443,8080,8443">
        </div>
      </div>
      <div class="actions">
        <button id="scan" class="primary">Start Scan</button>
        <button id="clear">Clear</button>
      </div>
    </aside>
    <section>
      <div class="toolbar">
        <div id="summary" class="summary">No results</div>
        <div class="result-actions">
          <button id="prev-page" disabled>Prev</button>
          <span id="page-label" class="page-label">Page 0/0</span>
          <button id="next-page" disabled>Next</button>
          <button id="download-json" disabled>JSON</button>
          <button id="download-csv" disabled>CSV</button>
        </div>
      </div>
      <div id="empty" class="empty">Results will appear here</div>
      <div id="table" class="table-wrap" hidden>
        <table>
          <thead>
            <tr>
              <th data-sort="is_valid">Valid</th>
              <th data-sort="ip">IP</th>
              <th data-sort="port">Port</th>
              <th data-sort="host">Host</th>
              <th data-sort="path">Path</th>
              <th data-sort="url">URL</th>
              <th data-sort="user_agent">User-Agent</th>
              <th data-sort="status_code">Status</th>
              <th data-sort="title">Title</th>
              <th data-sort="content_length">Length</th>
              <th data-sort="server">Server</th>
              <th data-sort="response_time_ms">Time</th>
              <th data-sort="error">Error</th>
            </tr>
          </thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
      <div class="log-panel">
        <div class="log-head">Scan Log</div>
        <pre id="logs" class="logs">No scan logs</pre>
      </div>
    </section>
  </main>
  <script>
    const els = {
      ips: document.getElementById('ips'),
      ipsFile: document.getElementById('ips-file'),
      loadIps: document.getElementById('load-ips'),
      clearIps: document.getElementById('clear-ips'),
      hosts: document.getElementById('hosts'),
      hostsFile: document.getElementById('hosts-file'),
      loadHosts: document.getElementById('load-hosts'),
      clearHosts: document.getElementById('clear-hosts'),
      taskId: document.getElementById('task-id'),
      path: document.getElementById('path'),
      headers: document.getElementById('headers'),
      threads: document.getElementById('threads'),
      qps: document.getElementById('qps'),
      timeout: document.getElementById('timeout'),
      ports: document.getElementById('ports'),
      scan: document.getElementById('scan'),
      clear: document.getElementById('clear'),
      status: document.getElementById('status'),
      summary: document.getElementById('summary'),
      empty: document.getElementById('empty'),
      table: document.getElementById('table'),
      rows: document.getElementById('rows'),
      logs: document.getElementById('logs'),
      prevPage: document.getElementById('prev-page'),
      nextPage: document.getElementById('next-page'),
      pageLabel: document.getElementById('page-label'),
      json: document.getElementById('download-json'),
      csv: document.getElementById('download-csv'),
      sortHeaders: Array.from(document.querySelectorAll('th[data-sort]')),
    };
    let lastResults = [];
    let logLines = [];
    let currentPage = 0;
    let currentSession = null;
    let pollTimer = null;
    let eventSource = null;
    let sortState = { key: '', direction: 'asc' };
    const pageSize = 100;
    const loadedFiles = { ips: '', hosts: '' };
    const maxPreviewChars = 20000;

    function payload() {
      return {
        ips: sourceText('ips', els.ips),
        hosts: sourceText('hosts', els.hosts),
        path: els.path.value,
        headers: els.headers.value,
        threads: Number(els.threads.value),
        qps: Number(els.qps.value),
        timeout: Number(els.timeout.value),
        ports: els.ports.value,
      };
    }

    function escapeText(value) {
      return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[ch]));
    }

    function sortedResults() {
      const rows = lastResults.filter(Boolean);
      if (!sortState.key) {
        return rows;
      }

      const direction = sortState.direction === 'desc' ? -1 : 1;
      return rows.slice().sort((a, b) => compareRows(a, b, sortState.key) * direction);
    }

    function compareRows(a, b, key) {
      const av = a[key];
      const bv = b[key];
      if (typeof av === 'number' || typeof bv === 'number' || typeof av === 'boolean' || typeof bv === 'boolean') {
        return Number(av || 0) - Number(bv || 0);
      }
      return String(av ?? '').localeCompare(String(bv ?? ''), undefined, { numeric: true, sensitivity: 'base' });
    }

    function updateSortHeaders() {
      els.sortHeaders.forEach(th => {
        th.classList.toggle('sort-asc', sortState.key === th.dataset.sort && sortState.direction === 'asc');
        th.classList.toggle('sort-desc', sortState.key === th.dataset.sort && sortState.direction === 'desc');
      });
    }

    function renderPage() {
      const displayResults = sortedResults();
      const total = displayResults.length;
      const maxPage = Math.max(0, Math.ceil(total / pageSize) - 1);
      currentPage = Math.min(currentPage, maxPage);
      const pageRows = total === 0 ? [] : displayResults.slice(currentPage * pageSize, currentPage * pageSize + pageSize);

      els.rows.innerHTML = pageRows.map(row => {
        const validClass = row.is_valid ? 'valid' : 'invalid';
        const validText = row.is_valid ? 'Yes' : 'No';
        return '<tr>' +
          '<td class="' + validClass + '">' + validText + '</td>' +
          '<td>' + escapeText(row.ip) + '</td>' +
          '<td>' + escapeText(row.port) + '</td>' +
          '<td>' + escapeText(row.host) + '</td>' +
          '<td>' + escapeText(row.path) + '</td>' +
          '<td>' + escapeText(row.url) + '</td>' +
          '<td>' + escapeText(row.user_agent) + '</td>' +
          '<td>' + escapeText(row.status_code) + '</td>' +
          '<td>' + escapeText(row.title) + '</td>' +
          '<td>' + escapeText(row.content_length) + '</td>' +
          '<td>' + escapeText(row.server) + '</td>' +
          '<td>' + escapeText(row.response_time_ms) + 'ms</td>' +
          '<td class="error">' + escapeText(row.error) + '</td>' +
        '</tr>';
      }).join('');

      els.empty.hidden = total > 0;
      els.table.hidden = total === 0;
      els.pageLabel.textContent = total === 0 ? 'Page 0/0' : 'Page ' + (currentPage + 1) + '/' + (maxPage + 1);
      els.prevPage.disabled = total === 0 || currentPage === 0;
      els.nextPage.disabled = total === 0 || currentPage >= maxPage;
      els.json.disabled = total === 0;
      els.csv.disabled = total === 0;
      updateSortHeaders();
    }

    function render(results) {
      lastResults = results;
      currentPage = 0;
      renderPage();
      updateSummary();
    }

    function updateSummary(statusData) {
      const resultCount = lastResults.filter(Boolean).length;
      const total = statusData && statusData.total ? statusData.total : 0;
      const status = statusData ? statusData.status : '';
      const resultFile = statusData && statusData.result_file ? ' | CSV: ' + statusData.result_file : '';
      if (status === 'running') {
        els.summary.textContent = (total > 0 ? 'Scanning: ' + resultCount + '/' + total + ' probes' : 'Scanning: ' + resultCount + ' results') + resultFile;
      } else if (status === 'failed') {
        els.summary.textContent = 'Failed: ' + (statusData.error || 'scan failed');
      } else {
        els.summary.textContent = (resultCount === 1 ? '1 result' : resultCount + ' results') + resultFile;
      }
    }

    function setTaskIdentity(id, resultFile) {
      if (id) {
        els.taskId.textContent = 'Task ' + id + (resultFile ? ' | ' + resultFile : '');
        localStorage.setItem('hostcollision:lastTaskId', id);
        const url = new URL(window.location.href);
        url.searchParams.set('id', id);
        window.history.replaceState(null, '', url);
      } else {
        els.taskId.textContent = 'No task';
        localStorage.removeItem('hostcollision:lastTaskId');
        const url = new URL(window.location.href);
        url.searchParams.delete('id');
        window.history.replaceState(null, '', url);
      }
    }

    function setResultAt(index, result) {
      if (!Number.isInteger(index) || index < 0 || !result) {
        return false;
      }
      const wasOnLatestPage = currentPage >= Math.max(0, Math.ceil(lastResults.filter(Boolean).length / pageSize) - 1);
      lastResults[index] = result;
      if (wasOnLatestPage) {
        currentPage = Math.max(0, Math.ceil(lastResults.filter(Boolean).length / pageSize) - 1);
      }
      return true;
    }

    function setLogAt(index, line) {
      if (!Number.isInteger(index) || index < 0) {
        return false;
      }
      logLines[index] = String(line ?? '');
      els.logs.textContent = logLines.filter(line => line !== undefined).join('\n');
      els.logs.scrollTop = els.logs.scrollHeight;
      return true;
    }

    function appendStatus(data) {
      if (Array.isArray(data.results) && data.results.length > 0) {
        const offset = Number.isInteger(data.result_offset) ? data.result_offset : lastResults.length;
        data.results.forEach((result, i) => setResultAt(offset + i, result));
      }
      if (Array.isArray(data.logs) && data.logs.length > 0) {
        const offset = Number.isInteger(data.log_offset) ? data.log_offset : logLines.length;
        data.logs.forEach((line, i) => setLogAt(offset + i, line));
      }
      renderPage();
      updateSummary(data);
    }

    function handleScanEvent(data, session) {
      if (currentSession !== session) {
        return;
      }
      if (data.result_file) {
        session.resultFile = data.result_file;
        setTaskIdentity(session.id, session.resultFile);
      }
      if (data.type === 'result') {
        const index = Number.isInteger(data.result_index) ? data.result_index : lastResults.length;
        setResultAt(index, data.result);
        if (index === (session.nextResultOffset || 0)) {
          session.nextResultOffset = index + 1;
        }
      } else if (data.type === 'log') {
        const index = Number.isInteger(data.log_index) ? data.log_index : logLines.length;
        setLogAt(index, data.log);
        if (index === (session.nextLogOffset || 0)) {
          session.nextLogOffset = index + 1;
        }
      }

      renderPage();
      updateSummary(data);

      if (data.type === 'finished' || data.type === 'failed') {
        stopPollTimer();
        stopEventStream();
        els.status.textContent = data.type === 'failed' ? 'Finishing after failure' : 'Finishing';
        pollStatus();
      }
    }

    function download(name, type, content) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function toCSV(results) {
      const header = ['IP','Port','Host','Input','Path','URL','StatusCode','Title','ContentLength','Server','UserAgent','ResponseTime(ms)','IsValid','Error'];
      const rows = results.map(r => [r.ip, r.port, r.host, r.input, r.path, r.url, r.status_code, r.title, r.content_length, r.server, r.user_agent, r.response_time_ms, r.is_valid, r.error]);
      return [header, ...rows].map(row => row.map(cell => {
        const value = sanitizeCSVCell(String(cell ?? ''));
        return '"' + value.replace(/"/g, '""') + '"';
      }).join(',')).join('\n');
    }

    function sanitizeCSVCell(value) {
      const trimmed = value.replace(/^[ \t\r\n]+/, '');
      if (/^[=+\-@]/.test(trimmed)) {
        return "'" + value;
      }
      return value;
    }

    function lineCount(text) {
      return text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#')).length;
    }

    function sourceText(kind, target) {
      return loadedFiles[kind] || target.value;
    }

    function previewText(text) {
      if (text.length <= maxPreviewChars) {
        return text;
      }
      return text.slice(0, maxPreviewChars) + '\n\n# Preview truncated. The full uploaded file will be used for scanning.';
    }

    function readFileInto(fileInput, target, label, kind) {
      const file = fileInput.files && fileInput.files[0];
      if (!file) {
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        const text = String(reader.result || '');
        loadedFiles[kind] = text;
        target.value = previewText(text);
        els.status.textContent = label + ': ' + lineCount(text) + ' lines';
        fileInput.value = '';
      };
      reader.onerror = () => {
        els.status.textContent = 'Failed to read ' + file.name;
        fileInput.value = '';
      };
      reader.readAsText(file);
    }

    function stopPolling() {
      if (pollTimer) {
        clearTimeout(pollTimer);
        pollTimer = null;
      }
      stopEventStream();
    }

    function stopPollTimer() {
      if (pollTimer) {
        clearTimeout(pollTimer);
        pollTimer = null;
      }
    }

    function stopEventStream() {
      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }
    }

    function connectEventStream(session) {
      if (!window.EventSource) {
        return false;
      }
      if (eventSource) {
        eventSource.close();
      }

      const source = new EventSource('/scan/events?id=' + encodeURIComponent(session.id));
      eventSource = source;

      const onEvent = event => {
        if (currentSession !== session) {
          source.close();
          return;
        }
        try {
          handleScanEvent(JSON.parse(event.data), session);
        } catch (err) {
          els.status.textContent = 'Stream parse failed';
        }
      };

      ['snapshot', 'result', 'log', 'finished', 'failed'].forEach(type => {
        source.addEventListener(type, onEvent);
      });
      source.onerror = () => {
        if (currentSession === session) {
          els.status.textContent = 'Scanning';
        } else {
          source.close();
        }
      };
      return true;
    }

    async function pollStatus() {
      if (!currentSession) {
        return;
      }
      const session = currentSession;
      try {
        const params = new URLSearchParams({
          id: session.id,
          result_offset: String(session.nextResultOffset),
          result_limit: String(pageSize),
          log_offset: String(session.nextLogOffset),
          log_limit: '200',
        });
        const res = await fetch('/scan/status?' + params.toString());
        if (currentSession !== session) {
          return;
        }
        if (!res.ok) {
          throw new Error(await res.text());
        }
        const data = await res.json();
        if (currentSession !== session) {
          return;
        }
        if (data.result_file) {
          session.resultFile = data.result_file;
          setTaskIdentity(session.id, session.resultFile);
        }
        session.nextResultOffset = Number.isFinite(data.next_result_offset) ? Math.max(session.nextResultOffset || 0, data.next_result_offset) : session.nextResultOffset;
        session.nextLogOffset = Number.isFinite(data.next_log_offset) ? Math.max(session.nextLogOffset || 0, data.next_log_offset) : session.nextLogOffset;
        appendStatus(data);

        const hasPendingResults = session.nextResultOffset < (data.result_count || 0);
        const hasPendingLogs = session.nextLogOffset < (data.log_count || 0);
        if (data.status === 'running' || hasPendingResults || hasPendingLogs) {
          pollTimer = setTimeout(pollStatus, data.status === 'running' ? 250 : 50);
        } else {
          if (eventSource) {
            eventSource.close();
            eventSource = null;
          }
          els.scan.disabled = false;
          els.status.textContent = data.status === 'failed' ? 'Failed' : 'Finished';
          currentSession = null;
        }
      } catch (err) {
        if (currentSession !== session) {
          return;
        }
        els.scan.disabled = false;
        els.status.textContent = 'Failed';
        els.summary.textContent = err.message || String(err);
        stopPolling();
        currentSession = null;
      }
    }

    function restoreTaskFromURL() {
      const id = new URLSearchParams(window.location.search).get('id');
      if (!id || currentSession) {
        return;
      }

      lastResults = [];
      logLines = [];
      currentPage = 0;
      currentSession = {
        id,
        nextResultOffset: 0,
        nextLogOffset: 0,
        resultFile: '',
      };
      setTaskIdentity(id, '');
      els.logs.textContent = 'Reconnecting to task ' + id;
      els.status.textContent = 'Reconnecting';
      els.scan.disabled = true;
      renderPage();
      connectEventStream(currentSession);
      pollStatus();
    }

    els.scan.addEventListener('click', async () => {
      stopPolling();
      els.scan.disabled = true;
      els.status.textContent = 'Starting';
      els.summary.textContent = 'Starting';
      lastResults = [];
      logLines = [];
      currentPage = 0;
      currentSession = null;
      els.logs.textContent = 'Starting scan';
      renderPage();
      try {
        const res = await fetch('/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload()),
        });
        if (!res.ok) {
          throw new Error(await res.text());
        }
        const data = await res.json();
        currentSession = {
          id: data.id,
          nextResultOffset: 0,
          nextLogOffset: 0,
          resultFile: data.result_file || '',
        };
        setTaskIdentity(data.id, data.result_file || '');
        els.status.textContent = 'Scanning';
        updateSummary({ status: 'running', total: data.total || 0, result_file: data.result_file || '' });
        connectEventStream(currentSession);
        pollStatus();
      } catch (err) {
        els.status.textContent = 'Failed';
        els.summary.textContent = err.message || String(err);
        els.scan.disabled = false;
      }
    });

    els.clear.addEventListener('click', () => {
      stopPolling();
      currentSession = null;
      logLines = [];
      els.logs.textContent = 'No scan logs';
      render([]);
      setTaskIdentity('', '');
      els.scan.disabled = false;
      els.status.textContent = 'Ready';
    });

    els.loadIps.addEventListener('click', () => els.ipsFile.click());
    els.loadHosts.addEventListener('click', () => els.hostsFile.click());
    els.ipsFile.addEventListener('change', () => readFileInto(els.ipsFile, els.ips, 'IP list', 'ips'));
    els.hostsFile.addEventListener('change', () => readFileInto(els.hostsFile, els.hosts, 'Host list', 'hosts'));
    els.ips.addEventListener('input', () => {
      loadedFiles.ips = '';
    });
    els.hosts.addEventListener('input', () => {
      loadedFiles.hosts = '';
    });
    els.clearIps.addEventListener('click', () => {
      loadedFiles.ips = '';
      els.ips.value = '';
      els.status.textContent = 'IP list cleared';
    });
    els.clearHosts.addEventListener('click', () => {
      loadedFiles.hosts = '';
      els.hosts.value = '';
      els.status.textContent = 'Host list cleared';
    });
    els.prevPage.addEventListener('click', () => {
      currentPage = Math.max(0, currentPage - 1);
      renderPage();
    });
    els.nextPage.addEventListener('click', () => {
      currentPage += 1;
      renderPage();
    });
    els.sortHeaders.forEach(th => {
      th.addEventListener('click', () => {
        const key = th.dataset.sort;
        if (sortState.key === key) {
          sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
        } else {
          sortState = { key, direction: 'asc' };
        }
        currentPage = 0;
        renderPage();
      });
    });

    els.json.addEventListener('click', () => {
      download('hostcollision-results.json', 'application/json', JSON.stringify(sortedResults(), null, 2));
    });

    els.csv.addEventListener('click', () => {
      download('hostcollision-results.csv', 'text/csv', toCSV(sortedResults()));
    });

    restoreTaskFromURL();
  </script>
</body>
</html>`
