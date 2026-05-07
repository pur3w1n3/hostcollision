# Host Collision

Host Collision 是一个 Host Header 碰撞扫描工具。它会连接目标 `IP:Port`，设置候选 `Host` 请求头，并记录不同 Host Header 下的 HTTP / HTTPS 响应差异。

Host Collision is a host-header collision scanner. It probes target `IP:Port` combinations with candidate `Host` headers and records HTTP / HTTPS responses.

## 功能特性

- 单一清晰的扫描模型：`Target IPs x Host Headers/URLs x Ports`
- 支持真实 HTTP / HTTPS GET 探测，并设置自定义 Host Header
- 支持并发线程数和 QPS 控制
- 支持随机常见浏览器 User-Agent
- 支持 `-H "Name: value"` 自定义请求头；自定义 `User-Agent` 会覆盖随机 UA
- Host 输入支持裸域名、域名路径和完整 URL
- 支持全局 URL 路径；当 Host 输入没有自带路径时，会自动拼接该路径
- IP 输入支持单 IP、CIDR、范围和通配段
- 支持 CSV / JSON 结果导出
- GUI 支持 Windows、Linux、macOS 三端打开
- GUI 支持通过文件导入大 IP / Host 列表
- GitHub Actions 自动测试、构建，并在 tag 发布时上传 Release 产物

## 工作原理

每次扫描都会真实发起 HTTP 或 HTTPS 请求到目标 IP：

```text
GET http://1.2.3.4:80/login?a=1
Host: example.com
User-Agent: <random or custom>
```

如果 Host 输入为完整 URL，例如 `https://example.com/admin?a=1`，工具会提取：

- Host Header: `example.com`
- Request Path: `/admin?a=1`

最终请求仍然连接目标 IP，而不是连接 URL 中的域名。

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

GUI 中的 `Target IPs` 和 `Host Headers / Domains / URLs` 支持两种输入方式：

- 直接粘贴文本
- 点击 Upload 按钮读取本地 `.txt` / `.csv` 文件

上传大文件时，界面只显示前一部分预览，扫描时仍会使用完整文件内容，避免超大文本直接塞入输入框导致浏览器卡顿。

`Optional URL Path` 可以填写 `/login?a=1` 或 `https://example.com/login?a=1`。如果 Host 输入为 `example.com`，扫描会请求 `http://IP:Port/login?a=1` 并设置 `Host: example.com`；如果 Host 输入本身已经是 `example.com/admin`，则优先使用输入里的 `/admin`。

`Headers` 每行一个请求头，例如：

```text
User-Agent: custom
X-Forwarded-For: 127.0.0.1
```

## CLI 使用

从文件读取 IP 和 Host 列表：

```bash
hostcollision -i examples/ips.txt -d examples/domains.txt
```

输出 JSON：

```bash
hostcollision -i examples/ips.txt -d examples/domains.txt -o result.json
```

单个或多个命令行输入：

```bash
hostcollision --ip 192.168.1.10 --host example.com
hostcollision --ip 192.168.1.10 --host example.com/admin
hostcollision --ip 192.168.1.10 --host https://example.com/login?a=1
hostcollision --ip 192.168.1.10 --ip 192.168.1.11 --host example.com --host test.com
```

IP 段输入：

```bash
hostcollision --ip 192.168.1.0/24 --host example.com
hostcollision --ip 192.168.1.1-20 --host example.com
hostcollision --ip 192.168.1.* --host example.com
```

给多个 Host 统一拼接 URL 路径：

```bash
hostcollision -i examples/ips.txt -d examples/domains.txt --path /login?a=1
hostcollision --ip 192.168.1.10 --host example.com --host test.com --url-path https://demo.local/admin
```

自定义请求头：

```bash
hostcollision --ip 192.168.1.10 --host example.com -H "User-Agent: custom" -H "X-Forwarded-For: 127.0.0.1"
```

自定义扫描参数：

```bash
hostcollision -i ips.txt -d hosts.txt -t 50 -q 20 -p 80,443,8080 -o result.csv
```

## 参数说明

| 参数 | 简写 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--gui` | `-g` | `false` | 启动 GUI 模式 |
| `--threads` | `-t` | `20` | 并发 worker 数 |
| `--qps` | `-q` | `30` | 每秒请求数 |
| `--timeout` | `-T` | `5` | 请求超时时间，单位秒 |
| `--ports` | `-p` | `80,443,8080,8443` | 逗号分隔的端口列表 |
| `--path` | 无 | 空 | 给未自带路径的 Host 拼接请求路径或 URL 路径 |
| `--url-path` | 无 | 空 | `--path` 的别名 |
| `--output` | `-o` | `result.csv` | 输出文件路径，支持 `.csv` / `.json` |
| `--ip-file` | `-i` | 空 | 目标 IP 列表文件，支持 IP 段 |
| `--host-file` | `-d` | 空 | Host Header / 域名 / URL 列表文件 |
| `--ip` | 无 | 空 | 单个目标 IP / CIDR / 范围 / 通配段，可重复传参 |
| `--host` | 无 | 空 | 单个 Host Header / 域名 / URL，可重复传参 |
| `--header` | `-H` | 空 | 自定义请求头，格式 `Name: value`，可重复传参 |

## GitHub Actions

仓库内置 `.github/workflows/build.yml`：

- 在 Windows、Linux、macOS 上运行 `go test ./...`
- 构建 Windows amd64、Linux amd64、Linux arm64、macOS amd64、macOS arm64 产物
- 自动上传构建产物到 workflow artifacts
- 推送 `v*` 标签时自动创建 GitHub Release，并上传三端二进制文件和 `SHA256SUMS.txt`

发布新版本：

```bash
git tag v0.0.1
git push origin v0.0.1
```

## English

Host Collision sends real HTTP/HTTPS GET requests to target IPs while setting candidate Host headers. Host inputs may be bare domains, domain paths, or full URLs. If a full URL is provided, the hostname is used as the Host header and the URL path/query is preserved for probing.

Quick start:

```bash
go mod download
go build -trimpath -ldflags="-s -w" -o hostcollision ./cmd
hostcollision -g
hostcollision -i examples/ips.txt -d examples/domains.txt
hostcollision --ip 192.168.1.10 --host example.com -H "User-Agent: custom"
```

Supported IP input formats:

- Single IP: `192.168.1.10`
- CIDR: `192.168.1.0/24`
- Range: `192.168.1.1-20`
- Wildcard: `192.168.1.*`

## 注意事项

- 仅用于授权测试、资产核验和防御性安全研究。
- 根据目标环境承受能力合理设置 QPS 和线程数。
- 不要对未授权目标进行扫描。

## 免责声明

本项目仅供授权安全测试、资产验证和防御性研究使用。请勿将其用于任何未获得明确授权的系统、网络或服务。因使用或滥用本工具造成的服务中断、数据损失、法律责任或其他后果，均由使用者自行承担，项目作者和贡献者不承担任何责任。

This project is provided for authorized security testing, asset verification, and defensive research only. Do not use it against systems you do not own or do not have explicit permission to test. The authors and contributors are not responsible for misuse, service disruption, data loss, legal consequences, or any other damage caused by this tool.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=pur3w1n3/hostcollision&type=Date)](https://star-history.com/#pur3w1n3/hostcollision&Date)
