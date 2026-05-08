package scanner

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointLoadSkipAndDedupe(t *testing.T) {
	t.Parallel()

	filename := filepath.Join(t.TempDir(), "scan.checkpoint")
	result := &CollisionResult{
		IP:   "192.0.2.10",
		Port: 80,
		Host: "example.com",
		Path: "/admin",
	}

	progress, err := NewCheckpoint(filename, false)
	if err != nil {
		t.Fatalf("NewCheckpoint(false): %v", err)
	}
	if err := progress.MarkResult(result); err != nil {
		t.Fatalf("MarkResult: %v", err)
	}
	if err := progress.MarkResult(result); err != nil {
		t.Fatalf("duplicate MarkResult: %v", err)
	}
	if !progress.ShouldSkip(result.IP, result.Port, HostTarget{Host: result.Host, Path: result.Path}) {
		t.Fatal("expected current checkpoint to skip marked result")
	}
	if err := progress.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	resumed, err := NewCheckpoint(filename, true)
	if err != nil {
		t.Fatalf("NewCheckpoint(true): %v", err)
	}
	defer resumed.Close()
	if resumed.Count() != 1 {
		t.Fatalf("expected 1 loaded checkpoint entry, got %d", resumed.Count())
	}
	if !resumed.ShouldSkip(result.IP, result.Port, HostTarget{Host: result.Host, Path: result.Path}) {
		t.Fatal("expected resumed checkpoint to skip marked result")
	}

	lines, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := len(splitNonEmptyLines(string(lines))); got != 1 {
		t.Fatalf("expected duplicate checkpoint marks to write 1 line, got %d", got)
	}
}

func TestResultWriterAppendKeepsExistingCSV(t *testing.T) {
	t.Parallel()

	filename := filepath.Join(t.TempDir(), "result.csv")
	first := &CollisionResult{IP: "192.0.2.10", Port: 80, Host: "one.example", Input: "one.example", Path: "/", URL: "http://192.0.2.10:80/", StatusCode: 200, IsValid: true}
	second := &CollisionResult{IP: "192.0.2.20", Port: 443, Host: "two.example", Input: "two.example", Path: "/login", URL: "https://192.0.2.20:443/login", StatusCode: 302, IsValid: true}

	writer, err := NewResultWriterWithOptions(filename, ResultWriterOptions{})
	if err != nil {
		t.Fatalf("NewResultWriterWithOptions initial: %v", err)
	}
	if err := writer.Write(first); err != nil {
		t.Fatalf("Write first: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close first writer: %v", err)
	}

	writer, err = NewResultWriterWithOptions(filename, ResultWriterOptions{Append: true})
	if err != nil {
		t.Fatalf("NewResultWriterWithOptions append: %v", err)
	}
	if err := writer.Write(second); err != nil {
		t.Fatalf("Write second: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close append writer: %v", err)
	}

	file, err := os.Open(filename)
	if err != nil {
		t.Fatalf("Open result CSV: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll CSV: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected header plus 2 rows, got %d records", len(records))
	}
	if records[1][0] != first.IP || records[2][0] != second.IP {
		t.Fatalf("unexpected CSV rows: %#v", records)
	}
}

func splitNonEmptyLines(value string) []string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
