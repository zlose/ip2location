package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	ip2location "github.com/ip2location/ip2location-go/v9"
	ip2proxy "github.com/ip2location/ip2proxy-go/v4"
)

const (
	defaultInputPath      = "ss.txt"
	defaultIPInputPath    = "ip.txt"
	defaultGeodataDir     = "geodata"
	defaultSSOutputPath   = "report-ss.md"
	defaultIPOutputPath   = "report-ip.md"
	defaultCountScope     = "peer"
	defaultIncludePrivate = false
	defaultTopN           = 20
	maxIssueRowsInReport  = 20
)

var (
	proxyPXRegex    = regexp.MustCompile(`PX(\d+)`)
	locationDBRegex = regexp.MustCompile(`DB(\d+)`)
	pidRegex        = regexp.MustCompile(`pid=(\d+)`)
)

type config struct {
	inputPath       string
	ipInputPath     string
	geodataDir      string
	proxyBinPath    string
	locationBinPath string
	ssOutputPath    string
	ipOutputPath    string
	countScope      string
	includePrivate  bool
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
	totalLines      int
	validIPHits     int
	uniqueIPs       int
	stateCounts     map[string]int
	localPortCounts map[string]int
	peerPortCounts  map[string]int
	pidCounts       map[string]int
	issues          []parseIssue
}

type ipCount struct {
	ip    string
	count int
}

type keyCount struct {
	key   string
	count int
}

type proxyRow struct {
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

type locationRow struct {
	ip        string
	count     int
	country   string
	region    string
	city      string
	isp       string
	domain    string
	usageType string
	asn       string
	asName    string
	timezone  string
}

type selectedBins struct {
	proxyPath    string
	locationPath string
	warnings     []string
}

type binCandidate struct {
	path  string
	name  string
	score int
}

func main() {
	cfg := parseFlags()
	if err := validateConfig(cfg); err != nil {
		exitWithErr(err)
	}

	bins, err := resolveBins(cfg)
	if err != nil {
		exitWithErr(err)
	}

	ssCounts, ssStats, ssParseIssues, err := parseSSFile(cfg)
	if err != nil {
		exitWithErr(err)
	}
	ssItems := sortedIPCounts(ssCounts)
	ssProxyRows, ssLocationRows, ssProxyIssues, ssLocationIssues, err := enrichItems(ssItems, bins)
	if err != nil {
		exitWithErr(err)
	}
	ssStats.uniqueIPs = len(ssItems)
	ssStats.issues = ssParseIssues
	ssReport := buildMarkdownReport(
		ssStats,
		ssItems,
		ssProxyRows,
		ssLocationRows,
		ssProxyIssues,
		ssLocationIssues,
		cfg,
		bins,
		"SS 连接 IP 分析报告",
		cfg.inputPath,
		cfg.countScope,
	)
	if err := os.WriteFile(cfg.ssOutputPath, []byte(ssReport), 0644); err != nil {
		exitWithErr(fmt.Errorf("写入 SS 报告失败: %w", err))
	}

	ipCounts, ipStats, ipParseIssues, err := parseIPFile(cfg)
	if err != nil {
		exitWithErr(err)
	}
	ipItems := sortedIPCounts(ipCounts)
	ipProxyRows, ipLocationRows, ipProxyIssues, ipLocationIssues, err := enrichItems(ipItems, bins)
	if err != nil {
		exitWithErr(err)
	}
	ipStats.uniqueIPs = len(ipItems)
	ipStats.issues = ipParseIssues
	ipReport := buildMarkdownReport(
		ipStats,
		ipItems,
		ipProxyRows,
		ipLocationRows,
		ipProxyIssues,
		ipLocationIssues,
		cfg,
		bins,
		"IP 清单分析报告",
		cfg.ipInputPath,
		"ip-file",
	)
	if err := os.WriteFile(cfg.ipOutputPath, []byte(ipReport), 0644); err != nil {
		exitWithErr(fmt.Errorf("写入 IP 报告失败: %w", err))
	}

	fmt.Printf("完成：已生成报告 %s, %s\n", cfg.ssOutputPath, cfg.ipOutputPath)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.inputPath, "input", defaultInputPath, "ss 输出文件路径")
	flag.StringVar(&cfg.ipInputPath, "ip-input", defaultIPInputPath, "IP 清单输入文件路径（每行 IP 或 IP:PORT）")
	flag.StringVar(&cfg.geodataDir, "geodata-dir", defaultGeodataDir, "BIN 文件目录（自动识别 IP2Location/IP2Proxy）")
	flag.StringVar(&cfg.proxyBinPath, "proxy-bin", "", "指定 IP2Proxy BIN 文件路径（可选）")
	flag.StringVar(&cfg.locationBinPath, "location-bin", "", "指定 IP2Location BIN 文件路径（可选）")
	flag.StringVar(&cfg.ssOutputPath, "ss-output", defaultSSOutputPath, "SS 分析 Markdown 报告输出路径")
	flag.StringVar(&cfg.ipOutputPath, "ip-output", defaultIPOutputPath, "IP 清单分析 Markdown 报告输出路径")
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
	if strings.TrimSpace(cfg.ssOutputPath) == "" {
		return fmt.Errorf("无效的 --ss-output: 不能为空")
	}
	if strings.TrimSpace(cfg.ipOutputPath) == "" {
		return fmt.Errorf("无效的 --ip-output: 不能为空")
	}
	if filepath.Clean(cfg.ssOutputPath) == filepath.Clean(cfg.ipOutputPath) {
		return fmt.Errorf("--ss-output 与 --ip-output 不能相同")
	}
	return nil
}

func resolveBins(cfg config) (selectedBins, error) {
	result := selectedBins{
		proxyPath:    strings.TrimSpace(cfg.proxyBinPath),
		locationPath: strings.TrimSpace(cfg.locationBinPath),
		warnings:     make([]string, 0),
	}

	if result.proxyPath != "" && !isFileReadable(result.proxyPath) {
		return selectedBins{}, fmt.Errorf("指定的 --proxy-bin 不可读: %s", result.proxyPath)
	}
	if result.locationPath != "" && !isFileReadable(result.locationPath) {
		return selectedBins{}, fmt.Errorf("指定的 --location-bin 不可读: %s", result.locationPath)
	}

	if result.proxyPath != "" && result.locationPath != "" {
		return result, nil
	}

	proxyCandidates, locationCandidates, err := discoverBinCandidates(cfg.geodataDir)
	if err != nil {
		return selectedBins{}, err
	}

	if result.proxyPath == "" && len(proxyCandidates) > 0 {
		result.proxyPath = selectBestBin(proxyCandidates).path
		if len(proxyCandidates) > 1 {
			result.warnings = append(result.warnings,
				fmt.Sprintf("检测到 %d 个 IP2Proxy BIN，已选择：%s", len(proxyCandidates), filepath.ToSlash(result.proxyPath)),
			)
		}
	}
	if result.locationPath == "" && len(locationCandidates) > 0 {
		result.locationPath = selectBestBin(locationCandidates).path
		if len(locationCandidates) > 1 {
			result.warnings = append(result.warnings,
				fmt.Sprintf("检测到 %d 个 IP2Location BIN，已选择：%s", len(locationCandidates), filepath.ToSlash(result.locationPath)),
			)
		}
	}

	if result.proxyPath == "" {
		result.warnings = append(result.warnings, "未找到 IP2Proxy BIN，代理查询结果将跳过。")
	}
	if result.locationPath == "" {
		result.warnings = append(result.warnings, "未找到 IP2Location BIN，地理查询结果将跳过。")
	}
	if result.proxyPath == "" && result.locationPath == "" {
		return selectedBins{}, fmt.Errorf("在目录 %s 未发现可用的 IP2Proxy/IP2Location BIN 文件", cfg.geodataDir)
	}

	return result, nil
}

func discoverBinCandidates(geodataDir string) ([]binCandidate, []binCandidate, error) {
	entries, err := os.ReadDir(geodataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 BIN 目录失败 %s: %w", geodataDir, err)
	}

	proxyCandidates := make([]binCandidate, 0)
	locationCandidates := make([]binCandidate, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		upper := strings.ToUpper(name)
		if filepath.Ext(upper) != ".BIN" {
			continue
		}

		fullPath := filepath.Join(geodataDir, name)
		if strings.Contains(upper, "IP2PROXY") {
			proxyCandidates = append(proxyCandidates, binCandidate{
				path:  fullPath,
				name:  name,
				score: scoreProxyBin(upper),
			})
			continue
		}
		if strings.Contains(upper, "IP2LOCATION") {
			locationCandidates = append(locationCandidates, binCandidate{
				path:  fullPath,
				name:  name,
				score: scoreLocationBin(upper),
			})
		}
	}
	return proxyCandidates, locationCandidates, nil
}

func scoreProxyBin(upperName string) int {
	score := 0
	if match := proxyPXRegex.FindStringSubmatch(upperName); len(match) == 2 {
		if n, err := strconv.Atoi(match[1]); err == nil {
			score += n
		}
	}
	if strings.Contains(upperName, "IPV6") {
		score += 100
	}
	return score
}

func scoreLocationBin(upperName string) int {
	score := 0
	if match := locationDBRegex.FindStringSubmatch(upperName); len(match) == 2 {
		if n, err := strconv.Atoi(match[1]); err == nil {
			score += n
		}
	}
	if strings.Contains(upperName, "IPV6") {
		score += 1000
	}
	return score
}

func selectBestBin(candidates []binCandidate) binCandidate {
	sorted := append([]binCandidate(nil), candidates...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].score != sorted[j].score {
			return sorted[i].score > sorted[j].score
		}
		return sorted[i].name < sorted[j].name
	})
	return sorted[0]
}

func isFileReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func parseSSFile(cfg config) (map[string]int, parseStats, []parseIssue, error) {
	file, err := os.Open(cfg.inputPath)
	if err != nil {
		return nil, parseStats{}, nil, fmt.Errorf("读取输入文件失败 %s: %w", cfg.inputPath, err)
	}
	defer file.Close()

	counts := make(map[string]int)
	stats := parseStats{
		stateCounts:     make(map[string]int),
		localPortCounts: make(map[string]int),
		peerPortCounts:  make(map[string]int),
		pidCounts:       make(map[string]int),
	}
	issues := make([]parseIssue, 0)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		stats.totalLines++
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) > 0 {
			state := strings.TrimSpace(fields[0])
			if state != "" {
				stats.stateCounts[state]++
			}
		}

		for _, pid := range extractPIDs(line) {
			stats.pidCounts[pid]++
		}

		if len(fields) >= 4 {
			if port, ok := extractPort(fields[3]); ok {
				stats.localPortCounts[port]++
			}
		}
		if len(fields) >= 5 {
			if port, ok := extractPort(fields[4]); ok {
				stats.peerPortCounts[port]++
			}
		}

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

func parseIPFile(cfg config) (map[string]int, parseStats, []parseIssue, error) {
	file, err := os.Open(cfg.ipInputPath)
	if err != nil {
		return nil, parseStats{}, nil, fmt.Errorf("读取 IP 输入文件失败 %s: %w", cfg.ipInputPath, err)
	}
	defer file.Close()

	counts := make(map[string]int)
	stats := parseStats{
		stateCounts:     make(map[string]int),
		localPortCounts: make(map[string]int),
		peerPortCounts:  make(map[string]int),
		pidCounts:       make(map[string]int),
	}
	issues := make([]parseIssue, 0)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		stats.totalLines++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		token := strings.Fields(line)[0]
		ip, ok := extractIP(token)
		if !ok {
			issues = append(issues, parseIssue{
				line:    stats.totalLines,
				reason:  "无法解析为 IP 或 IP:PORT",
				content: line,
			})
			continue
		}
		if !cfg.includePrivate && shouldFilterPrivate(ip) {
			continue
		}
		counts[ip.String()]++
		stats.validIPHits++
	}

	if err := scanner.Err(); err != nil {
		return nil, parseStats{}, nil, fmt.Errorf("扫描 IP 输入文件失败: %w", err)
	}

	return counts, stats, issues, nil
}

func enrichItems(items []ipCount, bins selectedBins) ([]proxyRow, []locationRow, []queryIssue, []queryIssue, error) {
	proxyRows := make([]proxyRow, 0)
	locationRows := make([]locationRow, 0)
	proxyIssues := make([]queryIssue, 0)
	locationIssues := make([]queryIssue, 0)
	var err error

	if bins.proxyPath != "" {
		proxyRows, proxyIssues, err = enrichWithIP2Proxy(items, bins.proxyPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	if bins.locationPath != "" {
		locationRows, locationIssues, err = enrichWithIP2Location(items, bins.locationPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	return proxyRows, locationRows, proxyIssues, locationIssues, nil
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

func sortedKeyCounts(counts map[string]int) []keyCount {
	items := make([]keyCount, 0, len(counts))
	for key, count := range counts {
		items = append(items, keyCount{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].key < items[j].key
	})
	return items
}

func extractPort(endpoint string) (string, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || endpoint == "*" {
		return "", false
	}
	if strings.HasPrefix(endpoint, "[") {
		idx := strings.Index(endpoint, "]")
		if idx <= 1 {
			return "", false
		}
		rest := endpoint[idx+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", false
		}
		port := rest[1:]
		if port == "*" || !isPortToken(port) {
			return "", false
		}
		return port, true
	}

	lastColon := strings.LastIndex(endpoint, ":")
	if lastColon <= 0 {
		return "", false
	}
	port := endpoint[lastColon+1:]
	if port == "*" || !isPortToken(port) {
		return "", false
	}
	return port, true
}

func extractPIDs(line string) []string {
	matches := pidRegex.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	pids := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		pid := strings.TrimSpace(m[1])
		if pid == "" {
			continue
		}
		if _, exists := seen[pid]; exists {
			continue
		}
		seen[pid] = struct{}{}
		pids = append(pids, pid)
	}
	return pids
}

func enrichWithIP2Proxy(items []ipCount, binPath string) ([]proxyRow, []queryIssue, error) {
	db, err := ip2proxy.OpenDB(binPath)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 IP2Proxy BIN 失败 %s: %w", binPath, err)
	}
	defer db.Close()

	rows := make([]proxyRow, 0, len(items))
	queryIssues := make([]queryIssue, 0)
	for _, item := range items {
		record, qErr := db.GetAll(item.ip)
		if qErr != nil {
			queryIssues = append(queryIssues, queryIssue{ip: item.ip, reason: qErr.Error()})
			rows = append(rows, proxyRow{
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

		rows = append(rows, proxyRow{
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

func enrichWithIP2Location(items []ipCount, binPath string) ([]locationRow, []queryIssue, error) {
	db, err := ip2location.OpenDB(binPath)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 IP2Location BIN 失败 %s: %w", binPath, err)
	}
	defer db.Close()

	rows := make([]locationRow, 0, len(items))
	queryIssues := make([]queryIssue, 0)
	for _, item := range items {
		record, qErr := db.Get_all(item.ip)
		if qErr != nil {
			queryIssues = append(queryIssues, queryIssue{ip: item.ip, reason: qErr.Error()})
			rows = append(rows, locationRow{
				ip:        item.ip,
				count:     item.count,
				country:   "N/A",
				region:    "N/A",
				city:      "N/A",
				isp:       "N/A",
				domain:    "N/A",
				usageType: "N/A",
				asn:       "N/A",
				asName:    "N/A",
				timezone:  "N/A",
			})
			continue
		}

		rows = append(rows, locationRow{
			ip:        item.ip,
			count:     item.count,
			country:   formatCountry(record.Country_short, record.Country_long),
			region:    valueOrDash(record.Region),
			city:      valueOrDash(record.City),
			isp:       valueOrDash(record.Isp),
			domain:    valueOrDash(record.Domain),
			usageType: valueOrDash(record.Usagetype),
			asn:       valueOrDash(record.Asn),
			asName:    valueOrDash(record.As),
			timezone:  valueOrDash(record.Timezone),
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
	lower := strings.ToLower(v)
	if strings.Contains(lower, "this parameter is unavailable") || strings.Contains(lower, "not supported") {
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
	proxyRows []proxyRow,
	locationRows []locationRow,
	proxyIssues []queryIssue,
	locationIssues []queryIssue,
	cfg config,
	bins selectedBins,
	reportTitle string,
	inputPath string,
	countScope string,
) string {
	var b strings.Builder
	now := time.Now().Format("2006-01-02 15:04:05 -0700 MST")
	stateItems := sortedKeyCounts(stats.stateCounts)
	localPortItems := sortedKeyCounts(stats.localPortCounts)
	peerPortItems := sortedKeyCounts(stats.peerPortCounts)
	pidItems := sortedKeyCounts(stats.pidCounts)

	b.WriteString(fmt.Sprintf("# %s\n\n", reportTitle))
	b.WriteString(fmt.Sprintf("- 生成时间：%s\n", now))
	b.WriteString(fmt.Sprintf("- 输入文件：`%s`\n", filepath.ToSlash(inputPath)))
	b.WriteString(fmt.Sprintf("- BIN 目录：`%s`\n", filepath.ToSlash(cfg.geodataDir)))
	b.WriteString(fmt.Sprintf("- 统计范围：`%s`\n", countScope))
	b.WriteString(fmt.Sprintf("- 包含私网地址：`%t`\n", cfg.includePrivate))
	if bins.proxyPath != "" {
		b.WriteString(fmt.Sprintf("- Proxy BIN：`%s`\n", filepath.ToSlash(bins.proxyPath)))
	} else {
		b.WriteString("- Proxy BIN：`未找到`\n")
	}
	if bins.locationPath != "" {
		b.WriteString(fmt.Sprintf("- Location BIN：`%s`\n\n", filepath.ToSlash(bins.locationPath)))
	} else {
		b.WriteString("- Location BIN：`未找到`\n\n")
	}

	b.WriteString("## 输入摘要\n\n")
	b.WriteString("| 指标 | 值 |\n")
	b.WriteString("| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| 总行数 | %d |\n", stats.totalLines))
	b.WriteString(fmt.Sprintf("| 有效 IP 次数 | %d |\n", stats.validIPHits))
	b.WriteString(fmt.Sprintf("| 去重 IP 数 | %d |\n", stats.uniqueIPs))
	b.WriteString(fmt.Sprintf("| 连接状态种类数 | %d |\n", len(stateItems)))
	b.WriteString(fmt.Sprintf("| 本地端口种类数 | %d |\n", len(localPortItems)))
	b.WriteString(fmt.Sprintf("| 对端端口种类数 | %d |\n", len(peerPortItems)))
	b.WriteString(fmt.Sprintf("| PID 数 | %d |\n", len(pidItems)))
	b.WriteString(fmt.Sprintf("| 解析失败行数 | %d |\n", len(stats.issues)))
	b.WriteString(fmt.Sprintf("| Proxy 查询失败 IP 数 | %d |\n", len(proxyIssues)))
	b.WriteString(fmt.Sprintf("| Location 查询失败 IP 数 | %d |\n\n", len(locationIssues)))

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

	b.WriteString("## 连接状态统计\n\n")
	b.WriteString("| 状态 | 连接数 |\n")
	b.WriteString("| --- | --- |\n")
	if len(stateItems) == 0 {
		b.WriteString("| - | - |\n")
	} else {
		for _, item := range stateItems {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", escapeMarkdown(item.key), item.count))
		}
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("## 本地端口统计（Top %d）\n\n", defaultTopN))
	b.WriteString("| 排名 | 本地端口 | 连接数 |\n")
	b.WriteString("| --- | --- | --- |\n")
	localTop := min(defaultTopN, len(localPortItems))
	if localTop == 0 {
		b.WriteString("| - | - | - |\n")
	} else {
		for i := 0; i < localTop; i++ {
			item := localPortItems[i]
			b.WriteString(fmt.Sprintf("| %d | %s | %d |\n", i+1, escapeMarkdown(item.key), item.count))
		}
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("## 对端端口统计（Top %d）\n\n", defaultTopN))
	b.WriteString("| 排名 | 对端端口 | 连接数 |\n")
	b.WriteString("| --- | --- | --- |\n")
	peerTop := min(defaultTopN, len(peerPortItems))
	if peerTop == 0 {
		b.WriteString("| - | - | - |\n")
	} else {
		for i := 0; i < peerTop; i++ {
			item := peerPortItems[i]
			b.WriteString(fmt.Sprintf("| %d | %s | %d |\n", i+1, escapeMarkdown(item.key), item.count))
		}
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("## PID 统计（Top %d）\n\n", defaultTopN))
	b.WriteString("| 排名 | PID | 连接数 |\n")
	b.WriteString("| --- | --- | --- |\n")
	pidTop := min(defaultTopN, len(pidItems))
	if pidTop == 0 {
		b.WriteString("| - | - | - |\n")
	} else {
		for i := 0; i < pidTop; i++ {
			item := pidItems[i]
			b.WriteString(fmt.Sprintf("| %d | %s | %d |\n", i+1, escapeMarkdown(item.key), item.count))
		}
	}
	b.WriteString("\n")

	b.WriteString("## Proxy 查询结果\n\n")
	b.WriteString("| IP | 出现次数 | 代理类型 | 国家 | 地区 | 城市 | ISP | 域名 | 使用类型 | ASN | 最近发现 | 威胁类型 | 住宅网络 | 服务提供商 | 欺诈评分 |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	if bins.proxyPath == "" {
		b.WriteString("| - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |\n")
	} else if len(proxyRows) == 0 {
		b.WriteString("| - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |\n")
	} else {
		for _, row := range proxyRows {
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

	b.WriteString("## Location 查询结果\n\n")
	b.WriteString("| IP | 出现次数 | 国家 | 地区 | 城市 | ISP | 域名 | 使用类型 | ASN | AS | 时区 |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	if bins.locationPath == "" {
		b.WriteString("| - | - | - | - | - | - | - | - | - | - | - |\n")
	} else if len(locationRows) == 0 {
		b.WriteString("| - | - | - | - | - | - | - | - | - | - | - |\n")
	} else {
		for _, row := range locationRows {
			b.WriteString(fmt.Sprintf(
				"| %s | %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				escapeMarkdown(row.ip),
				row.count,
				escapeMarkdown(row.country),
				escapeMarkdown(row.region),
				escapeMarkdown(row.city),
				escapeMarkdown(row.isp),
				escapeMarkdown(row.domain),
				escapeMarkdown(row.usageType),
				escapeMarkdown(row.asn),
				escapeMarkdown(row.asName),
				escapeMarkdown(row.timezone),
			))
		}
	}
	b.WriteString("\n")

	b.WriteString("## 错误与告警\n\n")
	if len(bins.warnings) == 0 {
		b.WriteString("- 无\n")
	} else {
		for _, warning := range bins.warnings {
			b.WriteString(fmt.Sprintf("- %s\n", escapeMarkdown(warning)))
		}
	}
	b.WriteString(fmt.Sprintf("- 解析失败行数：%d\n", len(stats.issues)))
	b.WriteString(fmt.Sprintf("- Proxy 查询失败 IP 数：%d\n", len(proxyIssues)))
	b.WriteString(fmt.Sprintf("- Location 查询失败 IP 数：%d\n\n", len(locationIssues)))

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

	if len(proxyIssues) > 0 {
		b.WriteString("### Proxy 查询失败样例（最多20条）\n\n")
		b.WriteString("| IP | 原因 |\n")
		b.WriteString("| --- | --- |\n")
		limit := min(maxIssueRowsInReport, len(proxyIssues))
		for i := 0; i < limit; i++ {
			issue := proxyIssues[i]
			b.WriteString(fmt.Sprintf("| %s | %s |\n", escapeMarkdown(issue.ip), escapeMarkdown(issue.reason)))
		}
		b.WriteString("\n")
	}

	if len(locationIssues) > 0 {
		b.WriteString("### Location 查询失败样例（最多20条）\n\n")
		b.WriteString("| IP | 原因 |\n")
		b.WriteString("| --- | --- |\n")
		limit := min(maxIssueRowsInReport, len(locationIssues))
		for i := 0; i < limit; i++ {
			issue := locationIssues[i]
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
