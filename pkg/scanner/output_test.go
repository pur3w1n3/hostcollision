package scanner

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{
			name:  "valid ports",
			input: "80,443, 8080",
			want:  []int{80, 443, 8080},
		},
		{
			name:  "ignores invalid ports",
			input: "0,abc,65536,8443",
			want:  []int{8443},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParsePorts(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParsePorts(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSaveResultsJSON(t *testing.T) {
	results := sampleResults()
	filename := filepath.Join(t.TempDir(), "results.json")

	if err := SaveResults(results, filename); err != nil {
		t.Fatalf("SaveResults JSON failed: %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read JSON output: %v", err)
	}

	var got []*CollisionResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal JSON output: %v", err)
	}

	if len(got) != len(results) {
		t.Fatalf("JSON result count = %d, want %d", len(got), len(results))
	}
	if got[0].IP != results[0].IP || got[0].Host != results[0].Host {
		t.Fatalf("unexpected JSON result: %#v", got[0])
	}
}

func TestSaveResultsCSV(t *testing.T) {
	results := sampleResults()
	filename := filepath.Join(t.TempDir(), "results.csv")

	if err := SaveResults(results, filename); err != nil {
		t.Fatalf("SaveResults CSV failed: %v", err)
	}

	file, err := os.Open(filename)
	if err != nil {
		t.Fatalf("open CSV output: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("read CSV output: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("CSV record count = %d, want 2", len(records))
	}
	if records[0][0] != "IP" || records[1][0] != results[0].IP {
		t.Fatalf("unexpected CSV records: %#v", records)
	}
}

func sampleResults() []*CollisionResult {
	return []*CollisionResult{
		{
			IP:           "127.0.0.1",
			Port:         80,
			Host:         "example.com",
			StatusCode:   200,
			Title:        "Example",
			ContentLen:   128,
			Server:       "test",
			ResponseTime: 12,
			Timestamp:    time.Unix(1, 0).UTC(),
			IsValid:      true,
		},
	}
}
