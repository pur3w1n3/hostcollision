package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"hostcollision/pkg/scanner"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
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

type scanResponse struct {
	Results []*scanner.CollisionResult `json:"results"`
	Count   int                        `json:"count"`
}

// StartNativeGUI starts the cross-platform browser GUI.
func StartNativeGUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/scan", serveScan)

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

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func serveScan(w http.ResponseWriter, r *http.Request) {
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
	if len(ips) == 0 || len(hosts) == 0 {
		http.Error(w, "at least one IP and one host header/domain are required", http.StatusBadRequest)
		return
	}
	scn.ScanTargets(ips, hosts)

	results := scn.GetResults()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(scanResponse{
		Results: results,
		Count:   len(results),
	})
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
    .status {
      min-width: 190px;
      text-align: right;
      color: var(--muted);
      font-size: 14px;
    }
    main {
      display: grid;
      grid-template-columns: minmax(300px, 390px) minmax(0, 1fr);
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
      min-height: 130px;
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
      margin-bottom: 12px;
    }
    .summary {
      color: var(--muted);
      font-size: 14px;
    }
    .result-actions {
      display: flex;
      gap: 8px;
    }
    .table-wrap {
      width: 100%;
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
    }
    tr:last-child td { border-bottom: 0; }
    .valid { color: var(--good); font-weight: 700; }
    .invalid { color: var(--bad); font-weight: 700; }
    .empty {
      display: grid;
      place-items: center;
      min-height: 280px;
      border: 1px dashed var(--line);
      border-radius: 8px;
      color: var(--muted);
      background: rgba(255,255,255,0.58);
    }
    .error {
      color: var(--warn);
      overflow-wrap: anywhere;
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
    <h1>Host Collision</h1>
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
          <button id="download-json" disabled>JSON</button>
          <button id="download-csv" disabled>CSV</button>
        </div>
      </div>
      <div id="empty" class="empty">Results will appear here</div>
      <div id="table" class="table-wrap" hidden>
        <table>
          <thead>
            <tr>
              <th>Valid</th>
              <th>IP</th>
              <th>Port</th>
              <th>Host</th>
              <th>Path</th>
              <th>URL</th>
              <th>User-Agent</th>
              <th>Status</th>
              <th>Title</th>
              <th>Length</th>
              <th>Server</th>
              <th>Time</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody id="rows"></tbody>
        </table>
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
      json: document.getElementById('download-json'),
      csv: document.getElementById('download-csv'),
    };
    let lastResults = [];
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

    function render(results) {
      lastResults = results;
      els.rows.innerHTML = results.map(row => {
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

      els.empty.hidden = results.length > 0;
      els.table.hidden = results.length === 0;
      els.summary.textContent = results.length === 1 ? '1 result' : results.length + ' results';
      els.json.disabled = results.length === 0;
      els.csv.disabled = results.length === 0;
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
        const value = String(cell ?? '');
        return '"' + value.replace(/"/g, '""') + '"';
      }).join(',')).join('\n');
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

    els.scan.addEventListener('click', async () => {
      els.scan.disabled = true;
      els.status.textContent = 'Scanning';
      els.summary.textContent = 'Scanning';
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
        render(data.results || []);
        els.status.textContent = 'Finished';
      } catch (err) {
        els.status.textContent = 'Failed';
        els.summary.textContent = err.message || String(err);
      } finally {
        els.scan.disabled = false;
      }
    });

    els.clear.addEventListener('click', () => {
      render([]);
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

    els.json.addEventListener('click', () => {
      download('hostcollision-results.json', 'application/json', JSON.stringify(lastResults, null, 2));
    });

    els.csv.addEventListener('click', () => {
      download('hostcollision-results.csv', 'text/csv', toCSV(lastResults));
    });
  </script>
</body>
</html>`
