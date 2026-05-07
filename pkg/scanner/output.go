package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SaveResults saves scan results as JSON or CSV.
func SaveResults(results []*CollisionResult, filename string) error {
	if filename == "" {
		return nil
	}

	if strings.EqualFold(filename[strings.LastIndex(filename, ".")+1:], "json") {
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

	if err := writer.Write([]string{"IP", "Port", "Host", "Input", "Path", "URL", "StatusCode", "Title", "ContentLength", "Server", "UserAgent", "ResponseTime(ms)", "IsValid", "Error"}); err != nil {
		return err
	}

	for _, r := range results {
		if err := writer.Write([]string{
			r.IP,
			strconv.Itoa(r.Port),
			r.Host,
			r.Input,
			r.Path,
			r.URL,
			strconv.Itoa(r.StatusCode),
			r.Title,
			strconv.Itoa(r.ContentLen),
			r.Server,
			r.UserAgent,
			strconv.FormatInt(r.ResponseTime, 10),
			fmt.Sprintf("%v", r.IsValid),
			r.Error,
		}); err != nil {
			return err
		}
	}

	return writer.Error()
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
