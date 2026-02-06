package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	ip2proxy "github.com/ip2location/ip2proxy-go/v4"
)

const (
	defaultInputPath          = "ss.txt"
	defaultBINPath            = "geodata/IP2LOCATION-LITE-DB11.IPV6.BIN"
	defaultOutputPath         = "report.md"
	defaultCountScope         = "peer"
	defaultIncludePrivate     = false
	defaultTopN               = 20
	maxIssueRowsInReport      = 20
	residentialDerivedWarning = "当前 SDK 未直接暴露 RESIDENTIAL 字段，报告中的“住宅网络”按 ProxyType==RES 推导。"
)

type config struct {
	inputPath      string
	binPath        string
	outputPath     string
	countScope     string
	includePrivate bool
}

type parseIssue struct {
	line    int
	reason  string
	content string
}

type queryIssue struct {
	ip     string
	reason string
}

type parseStats struct {
	totalLines  int
	validIPHits int
	uniqueIPs   int
	issues      []parseIssue
}

type ipCount struct {
	ip    string
	count int
}

type reportRow struct {
	ip          string
	count       int
	proxyType   string
	country     string
	region      string
	city        string
	isp         string
	domain      string
	usageType   string
	asn         string
	lastSeen    string
	threat      string
	residential string
	provider    string
	fraudScore  string
}

func main() {
	cfg := parseFlags()
	if err := validateConfig(cfg); err != nil {
		exitWithErr(err)
	}

	counts, stats, parseIssues, err := parseSSFile(cfg)
	if err != nil {
		exitWithErr(err)
	}

	items := sortedIPCounts(counts)
	rows, queryIssues, err := enrichWithIP2Proxy(items, cfg.binPath)
	if err != nil {
		exitWithErr(err)
	}

	stats.uniqueIPs = len(items)
	stats.issues = parseIssues

	report := buildMarkdownReport(stats, items, rows, queryIssues, cfg)
	if err := os.WriteFile(cfg.outputPath, []byte(report), 0644); err != nil {
		exitWithErr(fmt.Errorf("写入报告失败: %w", err))
	}

	fmt.Printf("完成：已生成报告 %s\n", cfg.outputPath)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.inputPath, "input", defaultInputPath, "ss 输出文件路径")
	flag.StringVar(&cfg.binPath, "bin", defaultBINPath, "BIN 文件路径")
	flag.StringVar(&cfg.outputPath, "output", defaultOutputPath, "Markdown 报告输出路径")
	flag.StringVar(&cfg.countScope, "count-scope", defaultCountScope, "统计范围: peer|local|all")
	flag.BoolVar(&cfg.includePrivate, "include-private", defaultIncludePrivate, "是否包含私网/回环/链路本地地址")
	flag.Parse()
	return cfg
}

func validateConfig(cfg config) error {
	switch cfg.countScope {
	case "peer", "local", "all":
	default:
		return fmt.Errorf("无效的 --count-scope: %s (仅支持 peer|local|all)", cfg.countScope)
	}
	return nil
}

func parseSSFile(cfg config) (map[string]int, parseStats, []parseIssue, error) {
	file, err := os.Open(cfg.inputPath)
	if err != nil {
		return nil, parseStats{}, nil, fmt.Errorf("读取输入文件失败 %s: %w", cfg.inputPath, err)
	}
	defer file.Close()

	counts := make(map[string]int)
	var stats parseStats
	issues := make([]parseIssue, 0)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		stats.totalLines++
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			issues = append(issues, parseIssue{
				line:    stats.totalLines,
				reason:  "列数不足，无法解析 Local/Peer 地址",
				content: line,
			})
			continue
		}

		targets := pickAddressTargets(fields[3], fields[4], cfg.countScope)
		for _, endpoint := range targets {
			ip, ok := extractIP(endpoint)
			if !ok {
				continue
			}
			if !cfg.includePrivate && shouldFilterPrivate(ip) {
				continue
			}
			key := ip.String()
			counts[key]++
			stats.validIPHits++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, parseStats{}, nil, fmt.Errorf("扫描输入文件失败: %w", err)
	}

	return counts, stats, issues, nil
}

func pickAddressTargets(local, peer, scope string) []string {
	switch scope {
	case "local":
		return []string{local}
	case "all":
		return []string{local, peer}
	default:
		return []string{peer}
	}
}

func extractIP(endpoint string) (net.IP, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || endpoint == "*" {
		return nil, false
	}

	if strings.HasPrefix(endpoint, "[") {
		idx := strings.Index(endpoint, "]")
		if idx <= 1 {
			return nil, false
		}
		return parseHostToIP(endpoint[1:idx])
	}

	lastColon := strings.LastIndex(endpoint, ":")
	if lastColon > 0 {
		port := endpoint[lastColon+1:]
		hostCandidate := endpoint[:lastColon]
		if isPortToken(port) {
			if ip, ok := parseHostToIP(hostCandidate); ok {
				return ip, true
			}
		}
	}

	return parseHostToIP(endpoint)
}

func parseHostToIP(host string) (net.IP, bool) {
	host = strings.TrimSpace(host)
	if host == "" || host == "*" {
		return nil, false
	}
	if zoneIdx := strings.Index(host, "%"); zoneIdx > 0 {
		host = host[:zoneIdx]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	return ip, true
}

func isPortToken(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	v, err := strconv.Atoi(s)
	return err == nil && v >= 0 && v <= 65535
}

func shouldFilterPrivate(ip net.IP) bool {
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

func sortedIPCounts(counts map[string]int) []ipCount {
	items := make([]ipCount, 0, len(counts))
	for ip, count := range counts {
		items = append(items, ipCount{ip: ip, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].ip < items[j].ip
	})
	return items
}

func enrichWithIP2Proxy(items []ipCount, binPath string) ([]reportRow, []queryIssue, error) {
	if _, err := os.Stat(binPath); err != nil {
		return nil, nil, fmt.Errorf("BIN 文件不可用 %s: %w", binPath, err)
	}

	db, err := ip2proxy.OpenDB(binPath)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 BIN 失败: %w", err)
	}
	defer db.Close()

	rows := make([]reportRow, 0, len(items))
	queryIssues := make([]queryIssue, 0)
	for _, item := range items {
		record, qErr := db.GetAll(item.ip)
		if qErr != nil {
			queryIssues = append(queryIssues, queryIssue{
				ip:     item.ip,
				reason: qErr.Error(),
			})
			rows = append(rows, reportRow{
				ip:          item.ip,
				count:       item.count,
				proxyType:   "N/A",
				country:     "N/A",
				region:      "N/A",
				city:        "N/A",
				isp:         "N/A",
				domain:      "N/A",
				usageType:   "N/A",
				asn:         "N/A",
				lastSeen:    "N/A",
				threat:      "N/A",
				residential: "N/A",
				provider:    "N/A",
				fraudScore:  "N/A",
			})
			continue
		}

		rows = append(rows, reportRow{
			ip:          item.ip,
			count:       item.count,
			proxyType:   valueOrDash(record.ProxyType),
			country:     formatCountry(record.CountryShort, record.CountryLong),
			region:      valueOrDash(record.Region),
			city:        valueOrDash(record.City),
			isp:         valueOrDash(record.Isp),
			domain:      valueOrDash(record.Domain),
			usageType:   valueOrDash(record.UsageType),
			asn:         valueOrDash(record.Asn),
			lastSeen:    valueOrDash(record.LastSeen),
			threat:      valueOrDash(record.Threat),
			residential: inferResidential(record.ProxyType),
			provider:    valueOrDash(record.Provider),
			fraudScore:  valueOrDash(record.FraudScore),
		})
	}

	return rows, queryIssues, nil
}

func formatCountry(short, long string) string {
	short = valueOrDash(short)
	long = valueOrDash(long)
	if short == "-" && long == "-" {
		return "-"
	}
	return fmt.Sprintf("%s/%s", short, long)
}

func valueOrDash(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	return v
}

func inferResidential(proxyType string) string {
	switch strings.ToUpper(strings.TrimSpace(proxyType)) {
	case "RES":
		return "是"
	case "", "-":
		return "-"
	default:
		return "否"
	}
}

func buildMarkdownReport(
	stats parseStats,
	items []ipCount,
	rows []reportRow,
	queryIssues []queryIssue,
	cfg config,
) string {
	var b strings.Builder
	now := time.Now().Format("2006-01-02 15:04:05 -0700 MST")

	b.WriteString("# IP 连接分析报告\n\n")
	b.WriteString(fmt.Sprintf("- 生成时间：%s\n", now))
	b.WriteString(fmt.Sprintf("- 输入文件：`%s`\n", cfg.inputPath))
	b.WriteString(fmt.Sprintf("- 数据库文件：`%s`\n\n", cfg.binPath))

	b.WriteString("## 输入摘要\n\n")
	b.WriteString("| 指标 | 值 |\n")
	b.WriteString("| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| 总行数 | %d |\n", stats.totalLines))
	b.WriteString(fmt.Sprintf("| 有效 IP 次数 | %d |\n", stats.validIPHits))
	b.WriteString(fmt.Sprintf("| 去重 IP 数 | %d |\n", stats.uniqueIPs))
	b.WriteString(fmt.Sprintf("| 解析失败行数 | %d |\n", len(stats.issues)))
	b.WriteString(fmt.Sprintf("| 查询失败 IP 数 | %d |\n\n", len(queryIssues)))

	b.WriteString(fmt.Sprintf("## Top %d IP 统计\n\n", defaultTopN))
	b.WriteString("| 排名 | IP | 出现次数 |\n")
	b.WriteString("| --- | --- | --- |\n")
	top := min(defaultTopN, len(items))
	for i := 0; i < top; i++ {
		item := items[i]
		b.WriteString(fmt.Sprintf("| %d | %s | %d |\n", i+1, escapeMarkdown(item.ip), item.count))
	}
	if top == 0 {
		b.WriteString("| - | - | - |\n")
	}
	b.WriteString("\n")

	b.WriteString("## 全量明细\n\n")
	b.WriteString("| IP | 出现次数 | 代理类型 | 国家 | 地区 | 城市 | ISP | 域名 | 使用类型 | ASN | 最近发现 | 威胁类型 | 住宅网络 | 服务提供商 | 欺诈评分 |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	if len(rows) == 0 {
		b.WriteString("| - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |\n")
	} else {
		for _, row := range rows {
			b.WriteString(fmt.Sprintf(
				"| %s | %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				escapeMarkdown(row.ip),
				row.count,
				escapeMarkdown(row.proxyType),
				escapeMarkdown(row.country),
				escapeMarkdown(row.region),
				escapeMarkdown(row.city),
				escapeMarkdown(row.isp),
				escapeMarkdown(row.domain),
				escapeMarkdown(row.usageType),
				escapeMarkdown(row.asn),
				escapeMarkdown(row.lastSeen),
				escapeMarkdown(row.threat),
				escapeMarkdown(row.residential),
				escapeMarkdown(row.provider),
				escapeMarkdown(row.fraudScore),
			))
		}
	}
	b.WriteString("\n")

	b.WriteString("## 错误与告警\n\n")
	b.WriteString(fmt.Sprintf("- 告警：%s\n", residentialDerivedWarning))
	b.WriteString(fmt.Sprintf("- 解析失败行数：%d\n", len(stats.issues)))
	b.WriteString(fmt.Sprintf("- 查询失败 IP 数：%d\n\n", len(queryIssues)))

	if len(stats.issues) > 0 {
		b.WriteString("### 解析失败样例（最多20条）\n\n")
		b.WriteString("| 行号 | 原因 | 原始内容 |\n")
		b.WriteString("| --- | --- | --- |\n")
		limit := min(maxIssueRowsInReport, len(stats.issues))
		for i := 0; i < limit; i++ {
			issue := stats.issues[i]
			b.WriteString(fmt.Sprintf(
				"| %d | %s | %s |\n",
				issue.line,
				escapeMarkdown(issue.reason),
				escapeMarkdown(issue.content),
			))
		}
		b.WriteString("\n")
	}

	if len(queryIssues) > 0 {
		b.WriteString("### 查询失败样例（最多20条）\n\n")
		b.WriteString("| IP | 原因 |\n")
		b.WriteString("| --- | --- |\n")
		limit := min(maxIssueRowsInReport, len(queryIssues))
		for i := 0; i < limit; i++ {
			issue := queryIssues[i]
			b.WriteString(fmt.Sprintf("| %s | %s |\n", escapeMarkdown(issue.ip), escapeMarkdown(issue.reason)))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func exitWithErr(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}
