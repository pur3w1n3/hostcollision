package scanner

import (
	"fmt"
	"net/http"
	"strings"
)

func ParseHeaders(values []string) (map[string]string, error) {
	headers := make(map[string]string)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}

		name, headerValue, ok := strings.Cut(value, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header %q, expected Name: value", value)
		}

		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		headerValue = strings.TrimSpace(headerValue)
		if name == "" || headerValue == "" {
			return nil, fmt.Errorf("invalid header %q, expected Name: value", value)
		}

		headers[name] = headerValue
	}

	return headers, nil
}

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(headers))
	for name, value := range headers {
		cloned[http.CanonicalHeaderKey(name)] = value
	}
	return cloned
}
