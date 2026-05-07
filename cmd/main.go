package main

import (
	"bufio"
	"fmt"
	"hostcollision/pkg/gui"
	"hostcollision/pkg/scanner"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	threads    int
	qps        int
	timeout    int
	ports      string
	path       string
	output     string
	ipFile     string
	hostFile   string
	guiMode    bool
	ipValues   []string
	hostValues []string
	headers    []string
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

	fmt.Printf("[*] Host header collision scan | IPs: %d | Hosts: %d | Ports: %d\n", len(ips), len(hosts), len(config.Ports))
	scn.ScanTargets(ips, hosts)

	fmt.Printf("\n[*] Scan finished, %d results\n", len(scn.GetResults()))
	if err := scanner.SaveResults(scn.GetResults(), output); err != nil {
		fmt.Printf("[!] Save failed: %v\n", err)
	} else {
		fmt.Printf("[*] Results saved to: %s\n", output)
	}
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
