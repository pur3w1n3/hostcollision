# Host Collision

Host Collision is a fast host-header collision scanner. It supports IP-to-domain and domain-to-IP probing from both CLI and GUI modes.

## Features

- Bidirectional scan modes: IP to domain, domain to IP
- Concurrency and QPS controls
- HTTP and HTTPS probing with custom Host headers
- CSV and JSON output
- Cross-platform GUI on Windows, Linux, and macOS
- GitHub Actions builds for Windows, Linux, and macOS

## Build

```bash
go mod download
go build -trimpath -ldflags="-s -w" -o hostcollision ./cmd
```

On Windows:

```powershell
go build -trimpath -ldflags="-s -w" -o hostcollision.exe .\cmd
```

## GUI

```bash
hostcollision -g
```

The GUI starts a local web interface and opens it in the default browser. If the browser does not open automatically, copy the printed local URL into a browser.

## CLI

IP to domain:

```bash
hostcollision -m ip2domain -i examples/ips.txt -d examples/domains.txt
```

Domain to IP:

```bash
hostcollision -m domain2ip -i examples/ips.txt -d examples/domains.txt -o result.json
```

Custom settings:

```bash
hostcollision -m ip2domain -i ips.txt -d domains.txt -t 50 -q 20 -p 80,443,8080 -o result.csv
```

## Options

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--gui` | `-g` | `false` | Start GUI mode |
| `--threads` | `-t` | `20` | Concurrent workers |
| `--qps` | `-q` | `30` | Requests per second |
| `--timeout` | `-T` | `5` | Request timeout in seconds |
| `--ports` | `-p` | `80,443,8080,8443` | Comma-separated port list |
| `--output` | `-o` | `result.csv` | Output file path |
| `--ip-file` | `-i` | empty | IP list file |
| `--domain-file` | `-d` | empty | Domain list file |
| `--mode` | `-m` | `ip2domain` | `ip2domain` or `domain2ip` |

## Notes

Use this tool only for authorized testing. Keep QPS and thread counts within limits that the target environment permits.
