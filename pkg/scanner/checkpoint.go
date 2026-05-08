package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Checkpoint tracks completed probe keys so interrupted scans can resume.
type Checkpoint struct {
	mu   sync.Mutex
	file *os.File
	done map[string]struct{}
}

// NewCheckpoint opens a checkpoint file. When resume is true, existing entries are loaded.
func NewCheckpoint(filename string, resume bool) (*Checkpoint, error) {
	if filename == "" {
		return nil, nil
	}

	checkpoint := &Checkpoint{
		done: make(map[string]struct{}),
	}
	if resume {
		if err := checkpoint.load(filename); err != nil {
			return nil, err
		}
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !resume {
		flags |= os.O_TRUNC
	}
	file, err := os.OpenFile(filename, flags, 0644)
	if err != nil {
		return nil, err
	}
	checkpoint.file = file
	return checkpoint, nil
}

func (c *Checkpoint) load(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key := strings.TrimSpace(scanner.Text())
		if key != "" {
			c.done[key] = struct{}{}
		}
	}
	return scanner.Err()
}

// ShouldSkip reports whether a probe has already been marked complete.
func (c *Checkpoint) ShouldSkip(ip string, port int, target HostTarget) bool {
	if c == nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.done[checkpointKey(ip, port, target.Host, target.Path)]
	return ok
}

// MarkResult records one completed probe.
func (c *Checkpoint) MarkResult(result *CollisionResult) error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := checkpointKey(result.IP, result.Port, result.Host, result.Path)
	if _, ok := c.done[key]; ok {
		return nil
	}
	if _, err := fmt.Fprintln(c.file, key); err != nil {
		return err
	}
	c.done[key] = struct{}{}
	return nil
}

// Count returns the number of loaded or written checkpoint entries.
func (c *Checkpoint) Count() int {
	if c == nil {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.done)
}

// Close closes the checkpoint file.
func (c *Checkpoint) Close() error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.file == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
}

func checkpointKey(ip string, port int, host string, path string) string {
	return strings.Join([]string{ip, strconv.Itoa(port), host, path}, "\t")
}
