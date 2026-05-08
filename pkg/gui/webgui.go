package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hostcollision/pkg/scanner"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
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

type GUIOptions struct {
	Username string
	Password string
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

type scanResultsResponse struct {
	ID         string                     `json:"id"`
	Status     string                     `json:"status"`
	Total      int                        `json:"total"`
	Count      int                        `json:"count"`
	Page       int                        `json:"page"`
	PageSize   int                        `json:"page_size"`
	TotalPages int                        `json:"total_pages"`
	Sort       string                     `json:"sort"`
	Direction  string                     `json:"direction"`
	ResultFile string                     `json:"result_file"`
	Results    []*scanner.CollisionResult `json:"results"`
}

type scanManager struct {
	mu         sync.Mutex
	sessions   map[string]*scanSession
	timeoutLog *guiFileLog
	guiLog     *guiFileLog
}

type scanSession struct {
	mu                sync.Mutex
	id                string
	status            string
	err               string
	total             int
	skipped           int
	resultCount       int
	logs              []string
	logBaseIndex      int
	recentResults     []*scanner.CollisionResult
	recentStartIndex  int
	resultFile        string
	resultWriter      *scanner.ResultWriter
	resultMu          sync.Mutex
	config            *scanner.Config
	ips               []string
	targets           []scanner.HostTarget
	portCount         int
	checkpoint        *scanner.Checkpoint
	checkpointFile    string
	cancel            context.CancelFunc
	guiLog            *guiFileLog
	subscribers       map[chan scanEvent]struct{}
	lastProgressAt    time.Time
	lastProgressCount int
	timeoutLogCount   int
	lastTimeoutLogAt  time.Time
	startedAt         time.Time
	finishedAt        *time.Time
}

type scanEvent struct {
	Type       string `json:"type"`
	Status     string `json:"status,omitempty"`
	Error      string `json:"error,omitempty"`
	Total      int    `json:"total,omitempty"`
	Count      int    `json:"count,omitempty"`
	Skipped    int    `json:"skipped,omitempty"`
	ResultFile string `json:"result_file,omitempty"`
	Log        string `json:"log,omitempty"`
	LogIndex   int    `json:"log_index"`
}

const (
	defaultStatusLimit = 100
	maxStatusLimit     = 500
	maxScanSessions    = 20
	scanSessionTTL     = 30 * time.Minute
	maxSessionLogs     = 1000
	maxRecentResults   = maxStatusLimit
	progressEventStep  = 100
	progressEventEvery = 250 * time.Millisecond
)

// StartNativeGUI starts the cross-platform browser GUI.
func StartNativeGUI(options ...GUIOptions) {
	var guiOptions GUIOptions
	if len(options) > 0 {
		guiOptions = options[0]
	}

	timeoutLog, err := newGUIFileLog("timeout.log")
	if err != nil {
		fmt.Printf("[!] Could not open GUI timeout log file: %v\n", err)
	}
	if timeoutLog != nil {
		defer timeoutLog.Close()
	}

	guiLog, err := newGUIFileLog("hostcollision-gui.log")
	if err != nil {
		fmt.Printf("[!] Could not open GUI execution log file: %v\n", err)
	}
	if guiLog != nil {
		defer guiLog.Close()
	}

	manager := newScanManager(timeoutLog, guiLog)
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/scan", manager.serveScan)
	mux.HandleFunc("/scan/stop", manager.serveScanStop)
	mux.HandleFunc("/scan/pause", manager.serveScanPause)
	mux.HandleFunc("/scan/resume", manager.serveScanResume)
	mux.HandleFunc("/scan/status", manager.serveScanStatus)
	mux.HandleFunc("/scan/results", manager.serveScanResults)
	mux.HandleFunc("/scan/download", manager.serveScanDownload)
	mux.HandleFunc("/scan/events", manager.serveScanEvents)

	var handler http.Handler = mux
	if guiOptions.Username != "" || guiOptions.Password != "" {
		handler = basicAuth(handler, guiOptions.Username, guiOptions.Password)
	}

	server := &http.Server{
		Addr:              "127.0.0.1:0",
		Handler:           handler,
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
	if guiOptions.Username != "" || guiOptions.Password != "" {
		fmt.Println("[*] GUI authentication is enabled")
	}
	if err := openBrowser(url); err != nil {
		fmt.Printf("[!] Could not open browser automatically: %v\n", err)
		fmt.Printf("[*] Open this URL manually: %s\n", url)
	}

	select {}
}

func newScanManager(timeoutLog *guiFileLog, guiLog *guiFileLog) *scanManager {
	return &scanManager{
		sessions:   make(map[string]*scanSession),
		timeoutLog: timeoutLog,
		guiLog:     guiLog,
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

func basicAuth(next http.Handler, username string, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUsername, gotPassword, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(gotUsername), []byte(username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(gotPassword), []byte(password)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="Host Collision"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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
	if len(config.Ports) == 0 {
		config.Ports = []int{80, 443}
	}

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

	session := m.newSession(cloneScanConfig(config), ips, targets, len(config.Ports))
	if err := session.openCheckpoint(false); err != nil {
		session.finish("failed", "could not open GUI checkpoint: "+err.Error(), 0, true)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.addLog("[*] Timeout/no-status log: timeout.log")
	session.addLog("[*] GUI execution log: hostcollision-gui.log")
	session.addLog("[*] GUI checkpoint: " + session.checkpointFile)
	session.addLog("[*] Browser log is summarized for large scans; full results are saved to the task CSV")

	if err := m.startSessionRun(session, false); err != nil {
		session.finish("failed", err.Error(), 0, true)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(scanStartResponse{
		ID:         session.id,
		Status:     session.status,
		Total:      session.total,
		ResultFile: session.resultFile,
	})
}

func (m *scanManager) startSessionRun(session *scanSession, appendResults bool) error {
	if err := session.openResultWriter(appendResults); err != nil {
		session.addLog("[!] Could not open GUI result CSV: " + err.Error())
		return err
	}
	session.addLog("[*] Result CSV: " + session.resultFile)

	scn := scanner.NewScanner(session.scanConfig())
	scn.SetStoreResults(false)
	scn.SetSkipCallback(session.shouldSkipCheckpoint)
	scn.SetResultCallback(session.addResult)
	scn.SetLogCallback(session.addFileLog)
	scn.SetTimeoutCallback(func(result *scanner.CollisionResult) {
		line := scanner.FormatTimeoutResult(result)
		if err := m.writeTimeoutLog(line); err != nil {
			session.addLog("[!] Could not write timeout log: " + err.Error())
		}
		if err := session.markCheckpoint(result); err != nil {
			session.addLog("[!] Could not write checkpoint: " + err.Error())
		}
		session.noteTimeoutLog(result)
	})

	ctx, cancel := context.WithCancel(context.Background())
	session.startRunning(cancel)
	go session.run(ctx, scn)
	return nil
}

func (m *scanManager) serveScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

	session.stop("requested from browser")

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(session.snapshot(0, 0, 0, 0))
}

func (m *scanManager) serveScanPause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := m.getSession(r.URL.Query().Get("id"))
	if session == nil {
		http.Error(w, "scan session not found", http.StatusNotFound)
		return
	}

	session.pause("requested from browser")

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(session.snapshot(0, 0, 0, 0))
}

func (m *scanManager) serveScanResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := m.getSession(r.URL.Query().Get("id"))
	if session == nil {
		http.Error(w, "scan session not found", http.StatusNotFound)
		return
	}
	if !session.canResume() {
		http.Error(w, "scan session is not paused", http.StatusConflict)
		return
	}
	if err := m.startSessionRun(session, true); err != nil {
		session.finish("failed", err.Error(), session.skippedCount(), true)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.addLog("[*] GUI scan resumed from checkpoint")

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(session.snapshot(0, 0, 0, 0))
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

func (m *scanManager) serveScanResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := m.getSession(r.URL.Query().Get("id"))
	if session == nil {
		http.Error(w, "scan session not found", http.StatusNotFound)
		return
	}

	page := parseNonNegativeInt(r.URL.Query().Get("page"), 0)
	pageSize := parseBoundedPositiveInt(r.URL.Query().Get("page_size"), defaultStatusLimit, maxStatusLimit)
	sortKey := normalizeResultSort(r.URL.Query().Get("sort"))
	direction := normalizeSortDirection(r.URL.Query().Get("dir"))

	response, err := session.resultPage(page, pageSize, sortKey, direction)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(response)
}

func (m *scanManager) serveScanDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := m.getSession(r.URL.Query().Get("id"))
	if session == nil {
		http.Error(w, "scan session not found", http.StatusNotFound)
		return
	}

	resultFile := session.resultFilename()
	if resultFile == "" {
		http.Error(w, "result file not available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", resultFile))
	http.ServeFile(w, r, resultFile)
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
			if event.Type == "finished" || event.Type == "failed" || event.Type == "stopped" || event.Type == "paused" {
				return
			}
		}
	}
}

func (m *scanManager) newSession(config *scanner.Config, ips []string, targets []scanner.HostTarget, portCount int) *scanSession {
	now := time.Now()
	session := &scanSession{
		id:          newSessionID(),
		status:      "running",
		total:       len(ips) * len(targets) * portCount,
		logs:        make([]string, 0),
		config:      config,
		ips:         append([]string(nil), ips...),
		targets:     append([]scanner.HostTarget(nil), targets...),
		portCount:   portCount,
		subscribers: make(map[chan scanEvent]struct{}),
		startedAt:   now,
		guiLog:      m.guiLog,
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

func writeGUIExecutionLog(logFile *guiFileLog, taskID string, line string) {
	if logFile == nil {
		return
	}
	_ = logFile.Write(fmt.Sprintf("task=%s %s", taskID, line))
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

func (s *scanSession) run(ctx context.Context, scn *scanner.Scanner) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.finish("failed", fmt.Sprintf("%v", recovered), scn.GetSkippedCount(), true)
		}
	}()

	ips, targets, portCount := s.scanInputs()
	s.addLog(fmt.Sprintf("[*] GUI scan started | IPs: %d | Hosts: %d | Ports: %d", len(ips), len(targets), portCount))
	scn.ScanHostTargetsContext(ctx, ips, targets)
	switch {
	case ctx.Err() != nil && s.isPausing():
		s.addLog(fmt.Sprintf("[*] GUI scan paused, %d results, %d timeout/no-status, %d skipped", scn.GetResultCount(), scn.GetTimeoutCount(), scn.GetSkippedCount()))
		s.finish("paused", "", scn.GetSkippedCount(), false)
		return
	case ctx.Err() != nil || s.isStopping():
		s.addLog(fmt.Sprintf("[!] GUI scan stopped, %d results, %d timeout/no-status, %d skipped", scn.GetResultCount(), scn.GetTimeoutCount(), scn.GetSkippedCount()))
		s.finish("stopped", "", scn.GetSkippedCount(), true)
		return
	}
	s.addLog(fmt.Sprintf("[*] GUI scan finished, %d results, %d timeout/no-status, %d skipped", scn.GetResultCount(), scn.GetTimeoutCount(), scn.GetSkippedCount()))
	s.finish("finished", "", scn.GetSkippedCount(), true)
}

func (s *scanSession) startRunning(cancel context.CancelFunc) {
	s.mu.Lock()
	s.status = "running"
	s.err = ""
	s.cancel = cancel
	s.finishedAt = nil
	s.broadcastLocked(s.stateEventLocked("progress"))
	s.mu.Unlock()
}

func (s *scanSession) stop(reason string) {
	s.mu.Lock()
	if s.status == "paused" {
		s.status = "stopped"
		s.finishedAt = timePtr(time.Now())
		s.cancel = nil
		s.broadcastLocked(s.stateEventLocked("stopped"))
		s.mu.Unlock()
		s.addLog("[!] Stop paused scan " + reason)
		s.closeCheckpoint()
		return
	}
	if s.status != "running" && s.status != "pausing" {
		s.mu.Unlock()
		return
	}
	s.status = "stopping"
	cancel := s.cancel
	event := s.stateEventLocked("stopping")
	s.broadcastLocked(event)
	s.mu.Unlock()

	s.addLog("[!] Stop scan " + reason)
	if cancel != nil {
		cancel()
	}
}

func (s *scanSession) pause(reason string) {
	s.mu.Lock()
	if s.status != "running" {
		s.mu.Unlock()
		return
	}
	s.status = "pausing"
	cancel := s.cancel
	event := s.stateEventLocked("pausing")
	s.broadcastLocked(event)
	s.mu.Unlock()

	s.addLog("[*] Pause scan " + reason)
	if cancel != nil {
		cancel()
	}
}

func (s *scanSession) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.status == "stopping"
}

func (s *scanSession) isPausing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.status == "pausing"
}

func (s *scanSession) canResume() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.status == "paused"
}

func (s *scanSession) skippedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.skipped
}

func (s *scanSession) addResult(result *scanner.CollisionResult) {
	if err := s.writeResult(result); err != nil {
		s.addLog("[!] Could not write result CSV: " + err.Error())
	}
	if err := s.markCheckpoint(result); err != nil {
		s.addLog("[!] Could not write checkpoint: " + err.Error())
	}

	s.mu.Lock()
	s.resultCount++
	s.recentResults = append(s.recentResults, result)
	if len(s.recentResults) > maxRecentResults {
		drop := len(s.recentResults) - maxRecentResults
		s.recentResults = append([]*scanner.CollisionResult(nil), s.recentResults[drop:]...)
		s.recentStartIndex += drop
	}
	if s.shouldBroadcastProgressLocked(time.Now()) {
		s.broadcastLocked(s.stateEventLocked("progress"))
	}
	s.mu.Unlock()
}

func (s *scanSession) addLog(line string) {
	s.mu.Lock()
	index := s.logBaseIndex + len(s.logs)
	s.logs = append(s.logs, line)
	if len(s.logs) > maxSessionLogs {
		drop := len(s.logs) - maxSessionLogs
		s.logs = append([]string(nil), s.logs[drop:]...)
		s.logBaseIndex += drop
	}
	event := s.stateEventLocked("log")
	event.Log = line
	event.LogIndex = index
	s.broadcastLocked(event)
	id := s.id
	guiLog := s.guiLog
	s.mu.Unlock()

	writeGUIExecutionLog(guiLog, id, line)
}

func (s *scanSession) addFileLog(line string) {
	s.mu.Lock()
	id := s.id
	guiLog := s.guiLog
	s.mu.Unlock()

	writeGUIExecutionLog(guiLog, id, line)
}

func (s *scanSession) noteTimeoutLog(result *scanner.CollisionResult) {
	now := time.Now()

	s.mu.Lock()
	s.timeoutLogCount++
	count := s.timeoutLogCount
	shouldLog := count <= 20 || count%500 == 0 || now.Sub(s.lastTimeoutLogAt) >= 5*time.Second
	if shouldLog {
		s.lastTimeoutLogAt = now
	}
	s.mu.Unlock()

	if !shouldLog {
		return
	}

	if result == nil {
		s.addLog(fmt.Sprintf("[~] %d timeout/no-status entries written to timeout.log", count))
		return
	}
	s.addLog(fmt.Sprintf("[~] %d timeout/no-status entries written to timeout.log | latest %s:%d%s -> Host: %s", count, result.IP, result.Port, result.Path, result.Host))
}

func (s *scanSession) shouldBroadcastProgressLocked(now time.Time) bool {
	if s.resultCount == 0 {
		return false
	}
	if s.resultCount-s.lastProgressCount >= progressEventStep || now.Sub(s.lastProgressAt) >= progressEventEvery {
		s.lastProgressCount = s.resultCount
		s.lastProgressAt = now
		return true
	}
	return false
}

func (s *scanSession) finish(status string, err string, skipped int, closeCheckpoint bool) {
	now := time.Now()

	s.mu.Lock()
	s.status = status
	s.err = err
	s.skipped = skipped
	if status == "paused" {
		s.finishedAt = nil
	} else {
		s.finishedAt = &now
	}
	s.lastProgressCount = s.resultCount
	s.lastProgressAt = now
	s.cancel = nil
	s.broadcastLocked(s.stateEventLocked(status))
	resultWriter := s.resultWriter
	s.resultWriter = nil
	s.mu.Unlock()

	if resultWriter != nil {
		s.resultMu.Lock()
		if closeErr := resultWriter.Close(); closeErr != nil {
			s.resultMu.Unlock()
			s.addLog("[!] Could not close result CSV: " + closeErr.Error())
		} else {
			s.resultMu.Unlock()
		}
	}
	if closeCheckpoint {
		s.closeCheckpoint()
	}
}

func (s *scanSession) openResultWriter(appendResults bool) error {
	filename := s.resultFilename()
	if filename == "" {
		filename = "hostcollision-gui-" + s.id + ".csv"
	}
	writer, err := scanner.NewResultWriterWithOptions(filename, scanner.ResultWriterOptions{Append: appendResults})
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

	s.resultMu.Lock()
	defer s.resultMu.Unlock()

	return writer.Write(result)
}

func (s *scanSession) openCheckpoint(resume bool) error {
	filename := s.checkpointFilename()
	progress, err := scanner.NewCheckpoint(filename, resume)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.checkpointFile = filename
	s.checkpoint = progress
	s.mu.Unlock()
	return nil
}

func (s *scanSession) checkpointFilename() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.checkpointFile != "" {
		return s.checkpointFile
	}
	return "hostcollision-gui-" + s.id + ".checkpoint"
}

func (s *scanSession) shouldSkipCheckpoint(ip string, port int, target scanner.HostTarget) bool {
	s.mu.Lock()
	progress := s.checkpoint
	s.mu.Unlock()

	return progress != nil && progress.ShouldSkip(ip, port, target)
}

func (s *scanSession) markCheckpoint(result *scanner.CollisionResult) error {
	s.mu.Lock()
	progress := s.checkpoint
	s.mu.Unlock()

	if progress == nil {
		return nil
	}
	return progress.MarkResult(result)
}

func (s *scanSession) closeCheckpoint() {
	s.mu.Lock()
	progress := s.checkpoint
	s.checkpoint = nil
	s.mu.Unlock()

	if progress != nil {
		_ = progress.Close()
	}
}

func (s *scanSession) scanConfig() *scanner.Config {
	s.mu.Lock()
	defer s.mu.Unlock()

	return cloneScanConfig(s.config)
}

func (s *scanSession) scanInputs() ([]string, []scanner.HostTarget, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.ips...), append([]scanner.HostTarget(nil), s.targets...), s.portCount
}

func (s *scanSession) resultFilename() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.resultFile
}

func (s *scanSession) resultPage(page int, pageSize int, sortKey string, direction string) (scanResultsResponse, error) {
	s.mu.Lock()
	id := s.id
	status := s.status
	total := s.total
	count := s.resultCount
	resultFile := s.resultFile
	s.mu.Unlock()

	totalPages := 0
	if count > 0 {
		totalPages = (count + pageSize - 1) / pageSize
	}
	if totalPages > 0 && page >= totalPages {
		page = totalPages - 1
	}
	if page < 0 {
		page = 0
	}

	var results []*scanner.CollisionResult
	if sortKey == "" {
		start := page * pageSize
		end := start + pageSize
		if end > count {
			end = count
		}
		if cachedResults, ok := s.recentResultPage(start, end); ok {
			results = cachedResults
		} else {
			var err error
			s.resultMu.Lock()
			results, err = readResultFilePage(resultFile, page, pageSize)
			s.resultMu.Unlock()
			if err != nil {
				return scanResultsResponse{}, err
			}
		}
	} else {
		var err error
		s.resultMu.Lock()
		results, err = readResultFile(resultFile)
		s.resultMu.Unlock()
		if err != nil {
			return scanResultsResponse{}, err
		}
		sortResults(results, sortKey, direction)

		count = len(results)
		totalPages = 0
		if count > 0 {
			totalPages = (count + pageSize - 1) / pageSize
		}
		if totalPages > 0 && page >= totalPages {
			page = totalPages - 1
		}
		start := page * pageSize
		if start > len(results) {
			start = len(results)
		}
		end := start + pageSize
		if end > len(results) {
			end = len(results)
		}
		results = results[start:end]
	}

	return scanResultsResponse{
		ID:         id,
		Status:     status,
		Total:      total,
		Count:      count,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		Sort:       sortKey,
		Direction:  direction,
		ResultFile: resultFile,
		Results:    results,
	}, nil
}

func (s *scanSession) recentResultPage(start int, end int) ([]*scanner.CollisionResult, bool) {
	if end <= start {
		return nil, true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	recentEnd := s.recentStartIndex + len(s.recentResults)
	if start < s.recentStartIndex || end > recentEnd {
		return nil, false
	}
	results := make([]*scanner.CollisionResult, end-start)
	copy(results, s.recentResults[start-s.recentStartIndex:end-s.recentStartIndex])
	return results, true
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

	events := make([]scanEvent, 0, 1+len(s.logs)+1)
	events = append(events, s.stateEventLocked("snapshot"))
	for index, logLine := range s.logs {
		event := s.stateEventLocked("log")
		event.Log = logLine
		event.LogIndex = s.logBaseIndex + index
		events = append(events, event)
	}
	if s.status == "finished" || s.status == "failed" || s.status == "stopped" || s.status == "paused" {
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
		Count:      s.resultCount,
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

	logs, nextLogOffset := sliceStrings(s.logs, s.logBaseIndex, logOffset, logLimit)

	return scanStatusResponse{
		ID:               s.id,
		Status:           s.status,
		Error:            s.err,
		Total:            s.total,
		Count:            s.resultCount,
		Skipped:          s.skipped,
		Results:          nil,
		ResultOffset:     resultOffset,
		NextResultOffset: s.resultCount,
		ResultCount:      s.resultCount,
		Logs:             logs,
		LogOffset:        nextLogOffset - len(logs),
		NextLogOffset:    nextLogOffset,
		LogCount:         s.logBaseIndex + len(s.logs),
		ResultFile:       s.resultFile,
		StartedAt:        s.startedAt,
		FinishedAt:       s.finishedAt,
	}
}

func sliceStrings(values []string, baseOffset, offset, limit int) ([]string, int) {
	if offset < baseOffset {
		offset = baseOffset
	}
	maxOffset := baseOffset + len(values)
	if offset > maxOffset {
		offset = maxOffset
	}
	start := offset - baseOffset
	end := start + limit
	if end > len(values) {
		end = len(values)
	}
	page := make([]string, end-start)
	copy(page, values[start:end])
	return page, baseOffset + end
}

func readResultFilePage(filename string, page int, pageSize int) ([]*scanner.CollisionResult, error) {
	if filename == "" {
		return nil, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	if _, err := reader.Read(); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}

	start := page * pageSize
	end := start + pageSize
	results := make([]*scanner.CollisionResult, 0, pageSize)
	validIndex := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) < 14 {
			continue
		}
		if validIndex >= start && validIndex < end {
			results = append(results, csvRecordToResult(record))
		}
		validIndex++
		if validIndex >= end {
			break
		}
	}
	return results, nil
}

func readResultFile(filename string) ([]*scanner.CollisionResult, error) {
	if filename == "" {
		return nil, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) <= 1 {
		return nil, nil
	}

	results := make([]*scanner.CollisionResult, 0, len(records)-1)
	for _, record := range records[1:] {
		if len(record) < 14 {
			continue
		}
		results = append(results, csvRecordToResult(record))
	}
	return results, nil
}

func csvRecordToResult(record []string) *scanner.CollisionResult {
	port, _ := strconv.Atoi(record[1])
	statusCode, _ := strconv.Atoi(record[6])
	contentLength, _ := strconv.Atoi(record[8])
	responseTime, _ := strconv.ParseInt(record[11], 10, 64)
	isValid, _ := strconv.ParseBool(record[12])

	return &scanner.CollisionResult{
		IP:           record[0],
		Port:         port,
		Host:         record[2],
		Input:        record[3],
		Path:         record[4],
		URL:          record[5],
		StatusCode:   statusCode,
		Title:        record[7],
		ContentLen:   contentLength,
		Server:       record[9],
		UserAgent:    record[10],
		ResponseTime: responseTime,
		IsValid:      isValid,
		Error:        record[13],
	}
}

func sortResults(results []*scanner.CollisionResult, sortKey string, direction string) {
	desc := direction == "desc"
	sort.SliceStable(results, func(i, j int) bool {
		cmp := compareResults(results[i], results[j], sortKey)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareResults(a *scanner.CollisionResult, b *scanner.CollisionResult, sortKey string) int {
	switch sortKey {
	case "is_valid":
		return compareBool(a.IsValid, b.IsValid)
	case "ip":
		return strings.Compare(a.IP, b.IP)
	case "port":
		return compareInt(a.Port, b.Port)
	case "host":
		return strings.Compare(a.Host, b.Host)
	case "path":
		return strings.Compare(a.Path, b.Path)
	case "url":
		return strings.Compare(a.URL, b.URL)
	case "user_agent":
		return strings.Compare(a.UserAgent, b.UserAgent)
	case "status_code":
		return compareInt(a.StatusCode, b.StatusCode)
	case "title":
		return strings.Compare(a.Title, b.Title)
	case "content_length":
		return compareInt(a.ContentLen, b.ContentLen)
	case "server":
		return strings.Compare(a.Server, b.Server)
	case "response_time_ms":
		return compareInt64(a.ResponseTime, b.ResponseTime)
	case "error":
		return strings.Compare(a.Error, b.Error)
	default:
		return 0
	}
}

func compareBool(a bool, b bool) int {
	return compareInt(boolToInt(a), boolToInt(b))
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func compareInt(a int, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareInt64(a int64, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func normalizeResultSort(value string) string {
	switch value {
	case "is_valid", "ip", "port", "host", "path", "url", "user_agent", "status_code", "title", "content_length", "server", "response_time_ms", "error":
		return value
	default:
		return ""
	}
}

func normalizeSortDirection(value string) string {
	if strings.EqualFold(value, "desc") {
		return "desc"
	}
	return "asc"
}

func cloneScanConfig(config *scanner.Config) *scanner.Config {
	if config == nil {
		return &scanner.Config{}
	}
	cloned := *config
	cloned.Ports = append([]int(nil), config.Ports...)
	if config.Headers != nil {
		cloned.Headers = make(map[string]string, len(config.Headers))
		for name, value := range config.Headers {
			cloned.Headers[name] = value
		}
	}
	return &cloned
}

func timePtr(value time.Time) *time.Time {
	return &value
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
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      margin-top: 16px;
    }
    .actions button {
      width: 100%;
      padding: 0 8px;
    }
    .actions button:nth-child(-n + 3) {
      grid-column: span 2;
    }
    .actions button:nth-child(n + 4) {
      grid-column: span 3;
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
    .page-jump {
      width: 72px;
      min-height: 30px;
      padding: 0 8px;
      font-size: 12px;
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
        <button id="pause-scan" disabled>Pause Scan</button>
        <button id="resume-scan" disabled>Resume Scan</button>
        <button id="stop-scan" disabled>Stop Scan</button>
        <button id="clear">Clear</button>
      </div>
    </aside>
    <section>
      <div class="toolbar">
        <div id="summary" class="summary">No results</div>
        <div class="result-actions">
          <button id="first-page" disabled>First</button>
          <button id="prev-page" disabled>Prev</button>
          <span id="page-label" class="page-label">Page 0/0</span>
          <input id="page-input" class="page-jump" type="number" min="1" value="1" aria-label="Page number">
          <button id="go-page" disabled>Go</button>
          <button id="next-page" disabled>Next</button>
          <button id="last-page" disabled>Last</button>
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
      pause: document.getElementById('pause-scan'),
      resume: document.getElementById('resume-scan'),
      stop: document.getElementById('stop-scan'),
      clear: document.getElementById('clear'),
      status: document.getElementById('status'),
      summary: document.getElementById('summary'),
      empty: document.getElementById('empty'),
      table: document.getElementById('table'),
      rows: document.getElementById('rows'),
      logs: document.getElementById('logs'),
      firstPage: document.getElementById('first-page'),
      prevPage: document.getElementById('prev-page'),
      nextPage: document.getElementById('next-page'),
      lastPage: document.getElementById('last-page'),
      pageLabel: document.getElementById('page-label'),
      pageInput: document.getElementById('page-input'),
      goPage: document.getElementById('go-page'),
      json: document.getElementById('download-json'),
      csv: document.getElementById('download-csv'),
      sortHeaders: Array.from(document.querySelectorAll('th[data-sort]')),
    };
    let pageResults = [];
    let resultCount = 0;
    let totalPages = 0;
    let logLines = [];
    let currentPage = 0;
    let currentSession = null;
    let pollTimer = null;
    let resultTimer = null;
    let eventSource = null;
    let resultsRequestSeq = 0;
    let sortState = { key: '', direction: 'asc' };
    const pageSize = 100;
    const maxLogLines = 1000;
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

    function updateSortHeaders() {
      els.sortHeaders.forEach(th => {
        th.classList.toggle('sort-asc', sortState.key === th.dataset.sort && sortState.direction === 'asc');
        th.classList.toggle('sort-desc', sortState.key === th.dataset.sort && sortState.direction === 'desc');
      });
    }

    function renderPage() {
      const total = resultCount;
      const maxPage = Math.max(0, totalPages - 1);
      currentPage = Math.min(currentPage, maxPage);

      els.rows.innerHTML = pageResults.map(row => {
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
      els.pageInput.disabled = total === 0;
      els.pageInput.max = String(maxPage + 1);
      els.pageInput.value = total === 0 ? '1' : String(currentPage + 1);
      els.firstPage.disabled = total === 0 || currentPage === 0;
      els.prevPage.disabled = total === 0 || currentPage === 0;
      els.nextPage.disabled = total === 0 || currentPage >= maxPage;
      els.lastPage.disabled = total === 0 || currentPage >= maxPage;
      els.goPage.disabled = total === 0;
      els.json.disabled = total === 0;
      els.csv.disabled = total === 0;
      updateSortHeaders();
    }

    function render(results) {
      pageResults = results;
      currentPage = 0;
      renderPage();
      updateSummary();
    }

    function updateSummary(statusData) {
      const total = statusData && statusData.total ? statusData.total : 0;
      const status = statusData ? statusData.status : '';
      const resultFile = statusData && statusData.result_file ? ' | CSV: ' + statusData.result_file : '';
      if (status === 'running') {
        els.summary.textContent = (total > 0 ? 'Scanning: ' + resultCount + '/' + total + ' probes' : 'Scanning: ' + resultCount + ' results') + resultFile;
      } else if (status === 'pausing') {
        els.summary.textContent = 'Pausing: ' + resultCount + ' results' + resultFile;
      } else if (status === 'paused') {
        els.summary.textContent = 'Paused: ' + resultCount + ' results' + resultFile;
      } else if (status === 'stopping') {
        els.summary.textContent = 'Stopping: ' + resultCount + ' results' + resultFile;
      } else if (status === 'stopped') {
        els.summary.textContent = 'Stopped: ' + resultCount + ' results' + resultFile;
      } else if (status === 'failed') {
        els.summary.textContent = 'Failed: ' + (statusData.error || 'scan failed');
      } else {
        els.summary.textContent = (resultCount === 1 ? '1 result' : resultCount + ' results') + resultFile;
      }
    }

    function downloadServerFile() {
      const id = currentSession ? currentSession.id : new URLSearchParams(window.location.search).get('id');
      if (!id) {
        return;
      }
      window.location.href = '/scan/download?id=' + encodeURIComponent(id);
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

    function setLogAt(index, line) {
      if (!Number.isInteger(index) || index < 0) {
        return false;
      }
      const text = String(line ?? '');
      const existing = logLines.find(entry => entry.index === index);
      if (existing) {
        existing.line = text;
      } else {
        logLines.push({ index, line: text });
        logLines.sort((a, b) => a.index - b.index);
        if (logLines.length > maxLogLines) {
          logLines.splice(0, logLines.length - maxLogLines);
        }
      }
      els.logs.textContent = logLines.map(entry => entry.line).join('\n');
      els.logs.scrollTop = els.logs.scrollHeight;
      return true;
    }

    function setScanControls(status) {
      const running = status === 'running';
      const paused = status === 'paused';
      const busy = status === 'starting' || status === 'pausing' || status === 'stopping';
      els.scan.disabled = running || paused || busy;
      els.pause.disabled = !running;
      els.resume.disabled = !paused;
      els.stop.disabled = !(running || paused || status === 'pausing');
    }

    function appendStatus(data) {
      if (currentSession && data.status) {
        currentSession.status = data.status;
        setScanControls(data.status);
      }
      if (Number.isInteger(data.result_count)) {
        resultCount = data.result_count;
      } else if (Number.isInteger(data.count)) {
        resultCount = data.count;
      }
      if (Array.isArray(data.logs) && data.logs.length > 0) {
        const offset = Number.isInteger(data.log_offset) ? data.log_offset : logLines.length;
        data.logs.forEach((line, i) => setLogAt(offset + i, line));
      }
      renderPage();
      updateSummary(data);
      scheduleResultFetch(500);
    }

    function scheduleResultFetch(delay) {
      if (!currentSession) {
        return;
      }
      if (resultTimer) {
        return;
      }
      resultTimer = setTimeout(() => {
        resultTimer = null;
        fetchResultsPage().catch(err => {
          if (currentSession) {
            els.status.textContent = 'Result refresh failed';
            els.summary.textContent = err.message || String(err);
          }
        });
      }, delay);
    }

    async function fetchResultsPage() {
      if (!currentSession) {
        return;
      }
      const session = currentSession;
      const requestSeq = ++resultsRequestSeq;
      const params = new URLSearchParams({
        id: session.id,
        page: String(currentPage),
        page_size: String(pageSize),
        sort: sortState.key,
        dir: sortState.direction,
      });
      const res = await fetch('/scan/results?' + params.toString());
      if (currentSession !== session || requestSeq !== resultsRequestSeq) {
        return;
      }
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const data = await res.json();
      if (currentSession !== session || requestSeq !== resultsRequestSeq) {
        return;
      }

      pageResults = Array.isArray(data.results) ? data.results : [];
      resultCount = Number.isInteger(data.count) ? data.count : pageResults.length;
      totalPages = Number.isInteger(data.total_pages) ? data.total_pages : Math.ceil(resultCount / pageSize);
      currentPage = Number.isInteger(data.page) ? data.page : currentPage;
      if (data.result_file) {
        session.resultFile = data.result_file;
        setTaskIdentity(session.id, session.resultFile);
      }
      renderPage();
      updateSummary(data);
    }

    function handleScanEvent(data, session) {
      if (currentSession !== session) {
        return;
      }
      if (data.status) {
        session.status = data.status;
        setScanControls(data.status);
      }
      if (data.result_file) {
        session.resultFile = data.result_file;
        setTaskIdentity(session.id, session.resultFile);
      }
      if (Number.isInteger(data.count)) {
        resultCount = data.count;
        scheduleResultFetch(500);
      }
      if (data.type === 'log') {
        const index = Number.isInteger(data.log_index) ? data.log_index : logLines.length;
        setLogAt(index, data.log);
        if (index === (session.nextLogOffset || 0)) {
          session.nextLogOffset = index + 1;
        }
      }

      renderPage();
      updateSummary(data);

      if (data.type === 'stopping') {
        setScanControls('stopping');
        els.status.textContent = 'Stopping';
      }
      if (data.type === 'pausing') {
        setScanControls('pausing');
        els.status.textContent = 'Pausing';
      }

      if (data.type === 'finished' || data.type === 'failed' || data.type === 'stopped' || data.type === 'paused') {
        stopPollTimer();
        stopEventStream();
        setScanControls(data.type);
        els.status.textContent = data.type === 'failed' ? 'Finishing after failure' : data.type === 'stopped' ? 'Stopped' : data.type === 'paused' ? 'Paused' : 'Finishing';
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
      if (resultTimer) {
        clearTimeout(resultTimer);
        resultTimer = null;
      }
      stopEventStream();
    }

    function goToPageFromInput() {
      if (!currentSession || resultCount === 0) {
        return;
      }
      const maxPage = Math.max(0, totalPages - 1);
      const requested = Number.parseInt(els.pageInput.value, 10);
      if (!Number.isFinite(requested)) {
        els.pageInput.value = String(currentPage + 1);
        return;
      }
      currentPage = Math.min(maxPage, Math.max(0, requested - 1));
      fetchResultsPage().catch(err => {
        els.status.textContent = 'Result refresh failed';
        els.summary.textContent = err.message || String(err);
      });
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

      ['snapshot', 'progress', 'log', 'pausing', 'paused', 'stopping', 'stopped', 'finished', 'failed'].forEach(type => {
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
        setScanControls(data.status);
        if (data.status === 'running' || data.status === 'pausing' || data.status === 'stopping' || hasPendingResults || hasPendingLogs) {
          pollTimer = setTimeout(pollStatus, data.status === 'running' || data.status === 'pausing' || data.status === 'stopping' ? 500 : 50);
        } else {
          if (eventSource) {
            eventSource.close();
            eventSource = null;
          }
          setScanControls(data.status);
          els.status.textContent = data.status === 'failed' ? 'Failed' : data.status === 'stopped' ? 'Stopped' : data.status === 'paused' ? 'Paused' : 'Finished';
        }
      } catch (err) {
        if (currentSession !== session) {
          return;
        }
        setScanControls('');
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

      pageResults = [];
      resultCount = 0;
      totalPages = 0;
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
      setScanControls('running');
      renderPage();
      connectEventStream(currentSession);
      pollStatus();
    }

    els.scan.addEventListener('click', async () => {
      stopPolling();
      setScanControls('starting');
      els.status.textContent = 'Starting';
      els.summary.textContent = 'Starting';
      pageResults = [];
      resultCount = 0;
      totalPages = 0;
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
        setScanControls('running');
        updateSummary({ status: 'running', total: data.total || 0, result_file: data.result_file || '' });
        connectEventStream(currentSession);
        fetchResultsPage().catch(err => {
          els.status.textContent = 'Result refresh failed';
          els.summary.textContent = err.message || String(err);
        });
        pollStatus();
      } catch (err) {
        els.status.textContent = 'Failed';
        els.summary.textContent = err.message || String(err);
        setScanControls('');
      }
    });

    els.stop.addEventListener('click', async () => {
      if (!currentSession) {
        return;
      }
      const session = currentSession;
      els.stop.disabled = true;
      els.status.textContent = 'Stopping';
      try {
        const res = await fetch('/scan/stop?id=' + encodeURIComponent(session.id), { method: 'POST' });
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
        appendStatus(data);
        stopPollTimer();
        pollStatus();
      } catch (err) {
        if (currentSession !== session) {
          return;
        }
        els.status.textContent = 'Stop failed';
        els.summary.textContent = err.message || String(err);
        els.stop.disabled = false;
      }
    });

    els.pause.addEventListener('click', async () => {
      if (!currentSession) {
        return;
      }
      const session = currentSession;
      setScanControls('pausing');
      els.status.textContent = 'Pausing';
      try {
        const res = await fetch('/scan/pause?id=' + encodeURIComponent(session.id), { method: 'POST' });
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
        appendStatus(data);
        stopPollTimer();
        pollStatus();
      } catch (err) {
        if (currentSession !== session) {
          return;
        }
        els.status.textContent = 'Pause failed';
        els.summary.textContent = err.message || String(err);
        setScanControls(session.status || 'running');
      }
    });

    els.resume.addEventListener('click', async () => {
      if (!currentSession) {
        return;
      }
      const session = currentSession;
      setScanControls('starting');
      els.status.textContent = 'Resuming';
      try {
        const res = await fetch('/scan/resume?id=' + encodeURIComponent(session.id), { method: 'POST' });
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
        appendStatus(data);
        els.status.textContent = 'Scanning';
        setScanControls('running');
        stopPollTimer();
        connectEventStream(session);
        fetchResultsPage().catch(err => {
          if (currentSession === session) {
            els.status.textContent = 'Result refresh failed';
            els.summary.textContent = err.message || String(err);
          }
        });
        pollStatus();
      } catch (err) {
        if (currentSession !== session) {
          return;
        }
        els.status.textContent = 'Resume failed';
        els.summary.textContent = err.message || String(err);
        setScanControls(session.status || 'paused');
      }
    });

    els.clear.addEventListener('click', () => {
      stopPolling();
      currentSession = null;
      logLines = [];
      pageResults = [];
      resultCount = 0;
      totalPages = 0;
      els.logs.textContent = 'No scan logs';
      render([]);
      setTaskIdentity('', '');
      setScanControls('');
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
    els.firstPage.addEventListener('click', () => {
      currentPage = 0;
      fetchResultsPage().catch(err => {
        els.status.textContent = 'Result refresh failed';
        els.summary.textContent = err.message || String(err);
      });
    });
    els.prevPage.addEventListener('click', () => {
      currentPage = Math.max(0, currentPage - 1);
      fetchResultsPage().catch(err => {
        els.status.textContent = 'Result refresh failed';
        els.summary.textContent = err.message || String(err);
      });
    });
    els.nextPage.addEventListener('click', () => {
      currentPage = Math.min(Math.max(0, totalPages - 1), currentPage + 1);
      fetchResultsPage().catch(err => {
        els.status.textContent = 'Result refresh failed';
        els.summary.textContent = err.message || String(err);
      });
    });
    els.lastPage.addEventListener('click', () => {
      currentPage = Math.max(0, totalPages - 1);
      fetchResultsPage().catch(err => {
        els.status.textContent = 'Result refresh failed';
        els.summary.textContent = err.message || String(err);
      });
    });
    els.goPage.addEventListener('click', goToPageFromInput);
    els.pageInput.addEventListener('keydown', event => {
      if (event.key === 'Enter') {
        goToPageFromInput();
      }
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
        fetchResultsPage().catch(err => {
          els.status.textContent = 'Result refresh failed';
          els.summary.textContent = err.message || String(err);
        });
      });
    });

    els.json.addEventListener('click', () => {
      download('hostcollision-current-page.json', 'application/json', JSON.stringify(pageResults, null, 2));
    });

    els.csv.addEventListener('click', () => {
      downloadServerFile();
    });

    restoreTaskFromURL();
  </script>
</body>
</html>`
