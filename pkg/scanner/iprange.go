package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ExpandIPInputs(values []string) ([]string, error) {
	seen := make(map[string]struct{})
	var result []string

	for _, value := range values {
		ips, err := expandIPInput(value)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			result = append(result, ip)
		}
	}

	return result, nil
}

func expandIPInput(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "#") {
		return nil, nil
	}

	if strings.Contains(value, "*") {
		return expandWildcardIPv4(value)
	}
	if strings.Contains(value, "/") {
		return expandCIDR(value)
	}
	if strings.Contains(value, "-") {
		return expandRangeIPv4(value)
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP input %q", value)
	}
	return []string{ip.String()}, nil
}

func expandCIDR(value string) ([]string, error) {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return []string{ip.String()}, nil
	}

	start := binary.BigEndian.Uint32(network.IP.To4())
	mask := binary.BigEndian.Uint32(network.Mask)
	end := start | ^mask

	var result []string
	for current := start; current <= end; current++ {
		if end-start > 1 && (current == start || current == end) {
			continue
		}
		result = append(result, uint32ToIPv4(current))
		if current == end {
			break
		}
	}
	return result, nil
}

func expandRangeIPv4(value string) ([]string, error) {
	left, right, ok := strings.Cut(value, "-")
	if !ok {
		return nil, fmt.Errorf("invalid IP range %q", value)
	}
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)

	startIP := net.ParseIP(left).To4()
	if startIP == nil {
		return nil, fmt.Errorf("invalid IP range start %q", left)
	}

	var endIP net.IP
	if strings.Count(right, ".") == 0 {
		parts := strings.Split(left, ".")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid short IP range %q", value)
		}
		endIP = net.ParseIP(strings.Join([]string{parts[0], parts[1], parts[2], right}, ".")).To4()
	} else {
		endIP = net.ParseIP(right).To4()
	}
	if endIP == nil {
		return nil, fmt.Errorf("invalid IP range end %q", right)
	}

	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)
	if end < start {
		return nil, fmt.Errorf("invalid IP range %q: end is before start", value)
	}

	var result []string
	for current := start; current <= end; current++ {
		result = append(result, uint32ToIPv4(current))
		if current == end {
			break
		}
	}
	return result, nil
}

func expandWildcardIPv4(value string) ([]string, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid wildcard IP %q", value)
	}

	ranges := make([][2]int, 4)
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "*" {
			ranges[i] = [2]int{0, 255}
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("invalid wildcard IP %q", value)
		}
		ranges[i] = [2]int{n, n}
	}

	var result []string
	for a := ranges[0][0]; a <= ranges[0][1]; a++ {
		for b := ranges[1][0]; b <= ranges[1][1]; b++ {
			for c := ranges[2][0]; c <= ranges[2][1]; c++ {
				for d := ranges[3][0]; d <= ranges[3][1]; d++ {
					result = append(result, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
				}
			}
		}
	}
	return result, nil
}

func uint32ToIPv4(value uint32) string {
	var ip [4]byte
	binary.BigEndian.PutUint32(ip[:], value)
	return net.IP(ip[:]).String()
}
