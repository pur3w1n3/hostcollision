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
	output     string
	ipFile     string
	domainFile string
	mode       string
	guiMode    bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "hostcollision",
		Short: "Host collision scanner for IP-to-domain and domain-to-IP probing",
		Run:   run,
	}

	rootCmd.Flags().BoolVarP(&guiMode, "gui", "g", false, "start GUI mode")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 20, "number of concurrent workers")
	rootCmd.Flags().IntVarP(&qps, "qps", "q", 30, "requests per second")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 5, "request timeout in seconds")
	rootCmd.Flags().StringVarP(&ports, "ports", "p", "80,443,8080,8443", "comma-separated port list")
	rootCmd.Flags().StringVarP(&output, "output", "o", "result.csv", "output file path (.csv/.json)")
	rootCmd.Flags().StringVarP(&ipFile, "ip-file", "i", "", "IP list file")
	rootCmd.Flags().StringVarP(&domainFile, "domain-file", "d", "", "domain list file")
	rootCmd.Flags().StringVarP(&mode, "mode", "m", "ip2domain", "scan mode: ip2domain/domain2ip")

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

	portList := scanner.ParsePorts(ports)
	config := &scanner.Config{
		Threads:    threads,
		QPS:        qps,
		Timeout:    timeout,
		Ports:      portList,
		OutputFile: output,
	}

	scn := scanner.NewScanner(config)

	switch mode {
	case "ip2domain":
		runIPToDomain(scn)
	case "domain2ip":
		runDomainToIP(scn)
	default:
		fmt.Printf("[!] Unknown mode %q, expected ip2domain or domain2ip\n", mode)
		os.Exit(1)
	}

	fmt.Printf("\n[*] Scan finished, %d results\n", len(scn.GetResults()))
	if err := scanner.SaveResults(scn.GetResults(), output); err != nil {
		fmt.Printf("[!] Save failed: %v\n", err)
	} else {
		fmt.Printf("[*] Results saved to: %s\n", output)
	}
}

func runIPToDomain(scn *scanner.Scanner) {
	ips := readLines(ipFile)
	domains := readLines(domainFile)
	fmt.Printf("[*] Mode: IP -> Domain | IPs: %d | Domains: %d\n", len(ips), len(domains))
	for _, ip := range ips {
		scn.ScanIPToDomains(ip, domains)
	}
}

func runDomainToIP(scn *scanner.Scanner) {
	domains := readLines(domainFile)
	ips := readLines(ipFile)
	fmt.Printf("[*] Mode: Domain -> IP | Domains: %d | IPs: %d\n", len(domains), len(ips))
	for _, domain := range domains {
		scn.ScanDomainToIPs(domain, ips)
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
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines
}
