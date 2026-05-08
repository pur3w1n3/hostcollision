package main

import (
	"bufio"
	"fmt"
	"hostcollision/pkg/gui"
	"hostcollision/pkg/scanner"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

var (
	threads        int
	qps            int
	timeout        int
	ports          string
	path           string
	output         string
	ipFile         string
	hostFile       string
	guiMode        bool
	resume         bool
	checkpoint     string
	logFile        string
	timeoutLogFile string
	ipValues       []string
	hostValues     []string
	headers        []string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "hostcollision",
		Short: "Host header collision scanner",
		Run:   run,
	}

	rootCmd.Flags().BoolVarP(&guiMode, "gui", "g", false, "start GUI mode")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 20, "number of concurrent workers")
	rootCmd.Flags().IntVarP(&qps, "qps", "q", 30, "requests per second")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 5, "request timeout in seconds")
	rootCmd.Flags().StringVarP(&ports, "ports", "p", "80,443,8080,8443", "comma-separated port list")
	rootCmd.Flags().StringVar(&path, "path", "", "optional request path or URL path appended to hosts without their own path")
	rootCmd.Flags().StringVar(&path, "url-path", "", "alias for --path")
	rootCmd.Flags().StringVarP(&output, "output", "o", "result.csv", "output file path (.csv/.json)")
	rootCmd.Flags().StringVarP(&ipFile, "ip-file", "i", "", "IP list file")
	rootCmd.Flags().StringVarP(&hostFile, "host-file", "d", "", "host header/domain list file")
	rootCmd.Flags().BoolVar(&resume, "resume", false, "resume from checkpoint and append CSV output")
	rootCmd.Flags().StringVar(&checkpoint, "checkpoint", "", "checkpoint file path, defaults to <output>.checkpoint")
	rootCmd.Flags().StringVar(&logFile, "log-file", "scan.log", "scan log file path")
	rootCmd.Flags().StringVar(&timeoutLogFile, "timeout-log-file", "timeout.log", "timeout/no-status probe log file path")
	rootCmd.Flags().StringArrayVar(&ipValues, "ip", nil, "target IP, CIDR, range, or wildcard, can be specified multiple times")
	rootCmd.Flags().StringArrayVar(&hostValues, "host", nil, "host header/domain, can be specified multiple times")
	rootCmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "custom request header, can be specified multiple times, e.g. -H \"User-Agent: test\"")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	if guiMode {
		gui.StartNativeGUI()
		return
	}

	ipInputs := normalizeList(append(readLines(ipFile), ipValues...))
	ips, err := scanner.ExpandIPInputs(ipInputs)
	if err != nil {
		fmt.Printf("[!] Invalid IP input: %v\n", err)
		os.Exit(1)
	}
	hosts := normalizeList(append(readLines(hostFile), hostValues...))
	if len(ips) == 0 || len(hosts) == 0 {
		fmt.Println("[!] At least one IP and one host header/domain are required")
		os.Exit(1)
	}
	parsedHeaders, err := scanner.ParseHeaders(headers)
	if err != nil {
		fmt.Printf("[!] Invalid header: %v\n", err)
		os.Exit(1)
	}

	config := &scanner.Config{
		Threads:    threads,
		QPS:        qps,
		Timeout:    timeout,
		Ports:      scanner.ParsePorts(ports),
		Path:       path,
		Headers:    parsedHeaders,
		OutputFile: output,
	}
	scn := scanner.NewScanner(config)
	scn.SetStoreResults(false)

	logWriter, err := newLogWriter(logFile)
	if err != nil {
		fmt.Printf("[!] Cannot open log file: %v\n", err)
		os.Exit(1)
	}
	defer logWriter.Close()
	logLine := func(message string) {
		fmt.Println(message)
		_ = logWriter.Write(message)
	}
	scn.SetLogCallback(logLine)

	timeoutLogWriter, err := newLogWriter(timeoutLogFile)
	if err != nil {
		fmt.Printf("[!] Cannot open timeout log file: %v\n", err)
		os.Exit(1)
	}
	defer timeoutLogWriter.Close()

	checkpointFile := checkpoint
	if checkpointFile == "" {
		checkpointFile = defaultCheckpointFile(output)
	}
	progress, err := scanner.NewCheckpoint(checkpointFile, resume)
	if err != nil {
		fmt.Printf("[!] Cannot open checkpoint file: %v\n", err)
		os.Exit(1)
	}
	defer progress.Close()
	scn.SetSkipCallback(progress.ShouldSkip)

	resultWriter, err := scanner.NewResultWriterWithOptions(output, scanner.ResultWriterOptions{Append: resume})
	if err != nil {
		fmt.Printf("[!] Cannot open output file: %v\n", err)
		os.Exit(1)
	}
	var resultErr error
	var resultErrMu sync.Mutex
	scn.SetResultCallback(func(result *scanner.CollisionResult) {
		if resultWriter != nil {
			if err := resultWriter.Write(result); err != nil {
				resultErrMu.Lock()
				if resultErr == nil {
					resultErr = err
				}
				resultErrMu.Unlock()
				return
			}
		}
		if err := progress.MarkResult(result); err != nil {
			resultErrMu.Lock()
			if resultErr == nil {
				resultErr = err
			}
			resultErrMu.Unlock()
		}
	})
	scn.SetTimeoutCallback(func(result *scanner.CollisionResult) {
		_ = timeoutLogWriter.Write(scanner.FormatTimeoutResult(result))
		if err := progress.MarkResult(result); err != nil {
			resultErrMu.Lock()
			if resultErr == nil {
				resultErr = err
			}
			resultErrMu.Unlock()
		}
	})

	logLine(fmt.Sprintf("[*] Host header collision scan | IPs: %d | Hosts: %d | Ports: %d", len(ips), len(hosts), len(config.Ports)))
	if resume {
		logLine(fmt.Sprintf("[*] Resume enabled | checkpoint: %s | loaded: %d", checkpointFile, progress.Count()))
	} else {
		logLine(fmt.Sprintf("[*] Checkpoint: %s", checkpointFile))
	}
	scn.ScanTargets(ips, hosts)

	if resultWriter != nil {
		err = resultWriter.Close()
	}
	resultErrMu.Lock()
	if err == nil {
		err = resultErr
	}
	resultErrMu.Unlock()

	logLine(fmt.Sprintf("[*] Scan finished, %d results, %d timeout/no-status, %d skipped", scn.GetResultCount(), scn.GetTimeoutCount(), scn.GetSkippedCount()))
	if err != nil {
		logLine(fmt.Sprintf("[!] Save failed: %v", err))
	} else if output != "" {
		logLine(fmt.Sprintf("[*] Results saved to: %s", output))
	}
}

type logWriter struct {
	mu   sync.Mutex
	file *os.File
}

func newLogWriter(filename string) (*logWriter, error) {
	if filename == "" {
		return &logWriter{}, nil
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &logWriter{file: file}, nil
}

func (w *logWriter) Write(message string) error {
	if w == nil || w.file == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := fmt.Fprintf(w.file, "%s %s\n", time.Now().Format(time.RFC3339), message)
	return err
}

func (w *logWriter) Close() error {
	if w == nil || w.file == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	err := w.file.Close()
	w.file = nil
	return err
}

func defaultCheckpointFile(output string) string {
	if output == "" {
		return "hostcollision.checkpoint"
	}
	return filepath.Clean(output) + ".checkpoint"
}

func readLines(filename string) []string {
	if filename == "" {
		return []string{}
	}

	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[!] Cannot open file %s: %v\n", filename, err)
		return []string{}
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines
}

func normalizeList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
