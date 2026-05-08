package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

// SaveResults saves scan results as JSON or CSV.
func SaveResults(results []*CollisionResult, filename string) error {
	if filename == "" {
		return nil
	}

	if isJSONFilename(filename) {
		return saveJSON(results, filename)
	}

	return saveCSV(results, filename)
}

func saveJSON(results []*CollisionResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func saveCSV(results []*CollisionResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writeCSVHeader(writer); err != nil {
		return err
	}

	for _, r := range results {
		if err := writeCSVResult(writer, r); err != nil {
			return err
		}
	}

	return writer.Error()
}

// ResultWriter writes scan results incrementally.
type ResultWriter struct {
	mu       sync.Mutex
	file     *os.File
	csv      *csv.Writer
	json     *json.Encoder
	isJSON   bool
	first    bool
	closed   bool
	firstErr error
}

// ResultWriterOptions controls incremental result output behavior.
type ResultWriterOptions struct {
	Append bool
}

// NewResultWriter creates a streaming result writer for CSV or JSON output.
func NewResultWriter(filename string) (*ResultWriter, error) {
	return NewResultWriterWithOptions(filename, ResultWriterOptions{})
}

// NewResultWriterWithOptions creates a streaming result writer for CSV or JSON output.
func NewResultWriterWithOptions(filename string, options ResultWriterOptions) (*ResultWriter, error) {
	if filename == "" {
		return nil, nil
	}
	if options.Append && isJSONFilename(filename) {
		return nil, fmt.Errorf("resume append is not supported for JSON output; use CSV output for --resume")
	}

	flags := os.O_CREATE | os.O_WRONLY
	if options.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	file, err := os.OpenFile(filename, flags, 0644)
	if err != nil {
		return nil, err
	}

	writer := &ResultWriter{
		file:   file,
		isJSON: isJSONFilename(filename),
		first:  true,
	}

	if writer.isJSON {
		writer.json = json.NewEncoder(file)
		writer.json.SetIndent("", "  ")
		if _, err := io.WriteString(file, "[\n"); err != nil {
			_ = file.Close()
			return nil, err
		}
		return writer, nil
	}

	writer.csv = csv.NewWriter(file)
	writeHeader := true
	if options.Append {
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		writeHeader = info.Size() == 0
	}
	if writeHeader {
		if err := writeCSVHeader(writer.csv); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	writer.csv.Flush()
	if err := writer.csv.Error(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return writer, nil
}

// Write appends one result to the output file.
func (w *ResultWriter) Write(result *CollisionResult) error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("result writer is closed")
	}
	if w.firstErr != nil {
		return w.firstErr
	}

	var err error
	if w.isJSON {
		if !w.first {
			_, err = io.WriteString(w.file, ",\n")
		}
		if err == nil {
			err = w.json.Encode(result)
		}
		w.first = false
	} else {
		err = writeCSVResult(w.csv, result)
		w.csv.Flush()
		if err == nil {
			err = w.csv.Error()
		}
	}

	if err != nil {
		w.firstErr = err
	}
	return err
}

// Close flushes and closes the output file.
func (w *ResultWriter) Close() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return w.firstErr
	}
	w.closed = true

	var err error
	if w.isJSON {
		_, err = io.WriteString(w.file, "\n]\n")
	} else {
		w.csv.Flush()
		err = w.csv.Error()
	}
	if closeErr := w.file.Close(); err == nil {
		err = closeErr
	}
	if w.firstErr != nil {
		return w.firstErr
	}
	return err
}

func writeCSVHeader(writer *csv.Writer) error {
	return writer.Write([]string{"IP", "Port", "Host", "Input", "Path", "URL", "StatusCode", "Title", "ContentLength", "Server", "UserAgent", "ResponseTime(ms)", "IsValid", "Error"})
}

func writeCSVResult(writer *csv.Writer, r *CollisionResult) error {
	return writer.Write([]string{
		sanitizeCSVCell(r.IP),
		strconv.Itoa(r.Port),
		sanitizeCSVCell(r.Host),
		sanitizeCSVCell(r.Input),
		sanitizeCSVCell(r.Path),
		sanitizeCSVCell(r.URL),
		strconv.Itoa(r.StatusCode),
		sanitizeCSVCell(r.Title),
		strconv.Itoa(r.ContentLen),
		sanitizeCSVCell(r.Server),
		sanitizeCSVCell(r.UserAgent),
		strconv.FormatInt(r.ResponseTime, 10),
		fmt.Sprintf("%v", r.IsValid),
		sanitizeCSVCell(r.Error),
	})
}

func sanitizeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed == "" {
		return value
	}

	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func isJSONFilename(filename string) bool {
	index := strings.LastIndex(filename, ".")
	if index < 0 {
		return false
	}
	return strings.EqualFold(filename[index+1:], "json")
}

// ParsePorts parses a comma-separated port list.
func ParsePorts(portStr string) []int {
	var result []int
	for _, p := range strings.Split(portStr, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil && port > 0 && port <= 65535 {
			result = append(result, port)
		}
	}
	return result
}
