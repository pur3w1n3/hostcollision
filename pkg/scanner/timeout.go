package scanner

import "fmt"

// FormatTimeoutResult formats a timeout/no-status probe for timeout log files.
func FormatTimeoutResult(result *CollisionResult) string {
	if result == nil {
		return "timeout/no-status result: <nil>"
	}
	return fmt.Sprintf(
		"timeout/no-status | ip=%s port=%d host=%s path=%s url=%s input=%s elapsed=%dms error=%s",
		result.IP,
		result.Port,
		result.Host,
		result.Path,
		result.URL,
		result.Input,
		result.ResponseTime,
		result.Error,
	)
}
