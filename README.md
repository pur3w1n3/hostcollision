# Host Collision

Host Collision 是一个 Host Header 碰撞扫描工具，支持通过 CLI 和跨平台 GUI 进行 IP 到域名、域名到 IP 的双向探测。

Host Collision is a host-header collision scanner with both CLI and cross-platform GUI modes.

## 功能特性

- 支持双向扫描：IP 到域名、域名到 IP
- 支持并发线程数和 QPS 控制
- 支持 HTTP / HTTPS 探测，并自动设置自定义 Host Header
- 支持 CSV / JSON 结果导出
- GUI 支持 Windows、Linux、macOS 三端打开
- GitHub Actions 自动构建 Windows、Linux、macOS 版本

## 编译

```bash
go mod download
go build -trimpath -ldflags="-s -w" -o hostcollision ./cmd
```

Windows:

```powershell
go build -trimpath -ldflags="-s -w" -o hostcollision.exe .\cmd
```

## GUI 使用

```bash
hostcollision -g
```

程序会启动一个本地 Web GUI，并自动用默认浏览器打开。如果浏览器没有自动打开，把终端里打印的本地 URL 复制到浏览器即可。

IP List 和 Domain List 支持两种输入方式：

- 直接粘贴文本
- 点击 GUI 里的 Upload 按钮读取本地 `.txt` / `.csv` 文件

上传大文件时，界面只显示前一部分预览，扫描时仍会使用完整文件内容，避免超大文本直接塞入输入框导致浏览器卡顿。

## CLI 使用

IP 到域名：

```bash
hostcollision -m ip2domain -i examples/ips.txt -d examples/domains.txt
```

域名到 IP：

```bash
hostcollision -m domain2ip -i examples/ips.txt -d examples/domains.txt -o result.json
```

自定义参数：

```bash
hostcollision -m ip2domain -i ips.txt -d domains.txt -t 50 -q 20 -p 80,443,8080 -o result.csv
```

## 参数说明

| 参数 | 简写 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--gui` | `-g` | `false` | 启动 GUI 模式 |
| `--threads` | `-t` | `20` | 并发 worker 数 |
| `--qps` | `-q` | `30` | 每秒请求数 |
| `--timeout` | `-T` | `5` | 请求超时时间，单位秒 |
| `--ports` | `-p` | `80,443,8080,8443` | 逗号分隔的端口列表 |
| `--output` | `-o` | `result.csv` | 输出文件路径，支持 `.csv` / `.json` |
| `--ip-file` | `-i` | 空 | IP 列表文件 |
| `--domain-file` | `-d` | 空 | 域名列表文件 |
| `--mode` | `-m` | `ip2domain` | 扫描模式：`ip2domain` / `domain2ip` |

## GitHub Actions

仓库内置 `.github/workflows/build.yml`：

- 在 Windows、Linux、macOS 上运行 `go test ./...`
- 构建 Windows amd64、Linux amd64、Linux arm64、macOS amd64、macOS arm64 产物
- 自动上传构建产物到 workflow artifacts

## English Quick Start

Build:

```bash
go mod download
go build -trimpath -ldflags="-s -w" -o hostcollision ./cmd
```

Start GUI:

```bash
hostcollision -g
```

Run CLI:

```bash
hostcollision -m ip2domain -i examples/ips.txt -d examples/domains.txt
hostcollision -m domain2ip -i examples/ips.txt -d examples/domains.txt -o result.json
```

## 注意事项

- 仅用于授权测试、资产核验和防御性安全研究。
- 根据目标环境承受能力合理设置 QPS 和线程数。
- 不要对未授权目标进行扫描。

## 免责声明

本项目仅供授权安全测试、资产验证和防御性研究使用。请勿将其用于任何未获得明确授权的系统、网络或服务。因使用或滥用本工具造成的服务中断、数据损失、法律责任或其他后果，均由使用者自行承担，项目作者和贡献者不承担任何责任。

This project is provided for authorized security testing, asset verification, and defensive research only. Do not use it against systems you do not own or do not have explicit permission to test. The authors and contributors are not responsible for misuse, service disruption, data loss, legal consequences, or any other damage caused by this tool.
