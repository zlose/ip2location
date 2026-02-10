# ip2location

基于 `ss -Hantp` 与 `ip.txt` 输入做 IP 统计，并使用 `geodata/` 下的 BIN 数据库分别查询：

- Proxy 信息（IP2Proxy）
- Location 信息（IP2Location）

最终生成两份中文 Markdown 报告：

- `report-ss.md`（来自 `ss.txt`）
- `report-ip.md`（来自 `ip.txt`）

## 功能特性

- 解析 `ss -Hantp` 文本，统计各 IP 出现次数
- 解析 `ip.txt`（每行 `IP` 或 `IP:PORT`），统计 IP 出现次数
- 统计连接状态分布（如 `ESTAB`、`LISTEN`、`SYN-RECV`）
- 统计端口分布（本地端口 / 对端端口）
- 统计 PID 连接分布
- 支持 IPv4/IPv6
- 支持计数范围：`peer | local | all`
- 自动扫描 `geodata/*.BIN`，识别并选择：
  - `IP2PROXY*.BIN`
  - `IP2LOCATION*.BIN`
- 报告中分区输出：
  - `Proxy 查询结果`
  - `Location 查询结果`
- 失败不中断：单 IP 查询失败会记录在“错误与告警”

## 依赖

- Go `1.25+`
- 第三方库：
  - `github.com/ip2location/ip2proxy-go/v4`
  - `github.com/ip2location/ip2location-go/v9`

## 数据准备

将 BIN 文件放到 `geodata/` 目录，例如：

```text
geodata/
  IP2PROXY-LITE-PX12.BIN
  IP2LOCATION-LITE-DB11.IPV6.BIN
```

默认输入文件：

- `ss.txt`（`ss -Hantp` 原始输出）
- `ip.txt`（每行 `IP` 或 `IP:PORT`）

## 快速开始

```bash
go run .
```

默认参数：

- `--input ss.txt`
- `--ip-input ip.txt`
- `--geodata-dir geodata`
- `--ss-output report-ss.md`
- `--ip-output report-ip.md`
- `--count-scope peer`
- `--include-private=false`

运行后会生成：`report-ss.md` 与 `report-ip.md`。

## CLI 参数

```bash
go run . \
  --input "ss.txt" \
  --ip-input "ip.txt" \
  --geodata-dir "geodata" \
  --proxy-bin "" \
  --location-bin "" \
  --ss-output "report-ss.md" \
  --ip-output "report-ip.md" \
  --count-scope "peer" \
  --include-private=false
```

- `--input`：`ss` 输出文件路径
- `--ip-input`：IP 清单文件路径（每行 `IP` 或 `IP:PORT`）
- `--geodata-dir`：BIN 目录（自动识别两类库）
- `--proxy-bin`：手工指定 IP2Proxy BIN（可选）
- `--location-bin`：手工指定 IP2Location BIN（可选）
- `--ss-output`：`ss` 分析报告输出路径
- `--ip-output`：`ip` 清单分析报告输出路径
- `--count-scope`：`peer|local|all`
- `--include-private`：是否包含私网/回环/链路本地地址

## 自动选库规则

未显式指定 `--proxy-bin/--location-bin` 时：

- 按文件名识别 BIN 类型（`IP2PROXY` / `IP2LOCATION`）
- 同类型多个 BIN 时自动择优：
  - Proxy：优先更高 `PX` 编号，含 `IPV6` 额外加权
  - Location：优先更高 `DB` 编号，含 `IPV6` 额外加权
- 选择结果会写入报告头部与告警区

## 报告结构

`report-ss.md` 与 `report-ip.md` 主要章节：

1. 输入摘要
2. Top 20 IP 统计
3. 连接状态统计
4. 本地端口统计（Top 20）
5. 对端端口统计（Top 20）
6. PID 统计（Top 20）
7. Proxy 查询结果
8. Location 查询结果
9. 错误与告警

表头全部为中文。

## 常见问题

### 1. 为什么很多字段是 `-`？

- 对于 Proxy 查询：IP 不在 IP2Proxy 数据覆盖范围内时会是 `-`
- 对于 Location 查询：当前 DB 套餐不含某字段时会是 `-`

### 2. 如果只存在一种 BIN 会怎样？

工具不会中断，会输出已有类型的查询结果；缺失类型会在“错误与告警”中提示。

### 3. 为什么程序报“未发现可用 BIN”？

检查 `geodata/` 目录是否存在可读的 `*.BIN` 文件，且文件名包含 `IP2PROXY` 或 `IP2LOCATION`。
