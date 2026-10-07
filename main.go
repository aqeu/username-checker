package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	BaseURL           string
	Method            string
	RequestBody       string
	Headers           []string
	Cookies           []string
	Mode              string
	Length            int
	Prefix            string
	Suffix            string
	Seed              int64
	TotalChecks       int
	ThreadCount       int
	OutputFile        string
	OutputAllFile     string
	OutputFormat      string
	RequestTimeout    time.Duration
	OverallTimeout    time.Duration
	UAFile            string
	Delay             time.Duration
	DelayJitter       time.Duration
	Retries           int
	MaxBackoff        time.Duration
	Proxy             string
	ProxyFile         string
	ProxyType         string
	Quiet             bool
	Verbose           bool
	LogLevel          string
	LogFile           string
	CheckFile         string
	ResumeFile        string
	StatsInterval     time.Duration
	RateLimit         float64
	RateLimitBurst    int
	PerProxyRateLimit float64
	HeaderFile        string
	AvailableStatuses []int
	TakenStatuses     []int
	RetryStatuses     []int
	AvailableBody     string
	AvailableRegex    string
	WebhookURL        string
	DryRun            bool
	TLSInsecure       bool
	BasicAuth         string
	BearerToken       string
	MaxIdleConns      int
	IdleConnTimeout   time.Duration
}

var defaultConfig = Config{
	BaseURL:           "https://github.com/%s",
	Method:            "GET",
	Mode:              "letters",
	Length:            4,
	TotalChecks:       100,
	ThreadCount:       10,
	OutputFile:        "available.txt",
	OutputFormat:      "plain",
	RequestTimeout:    5 * time.Second,
	Retries:           2,
	MaxBackoff:        5 * time.Second,
	ProxyType:         "http",
	LogLevel:          "info",
	StatsInterval:     10 * time.Second,
	AvailableStatuses: []int{404},
	TakenStatuses:     []int{200},
	RetryStatuses:     []int{429, 500, 502, 503, 504},
	MaxIdleConns:      100,
	IdleConnTimeout:   90 * time.Second,
}

type LeveledLogger struct {
	*log.Logger
	level int
}

const (
	LogDebug = iota
	LogInfo
	LogWarn
	LogError
)

func NewLeveledLogger(w io.Writer, levelStr string) *LeveledLogger {
	level := LogInfo
	switch strings.ToLower(levelStr) {
	case "debug":
		level = LogDebug
	case "info":
		level = LogInfo
	case "warn":
		level = LogWarn
	case "error":
		level = LogError
	}
	return &LeveledLogger{
		Logger: log.New(w, "", log.LstdFlags),
		level:  level,
	}
}

func (l *LeveledLogger) Debug(v ...interface{}) {
	if l.level <= LogDebug {
		l.Logger.Print("[DEBUG] ", fmt.Sprint(v...))
	}
}
func (l *LeveledLogger) Debugf(format string, v ...interface{}) {
	if l.level <= LogDebug {
		l.Logger.Printf("[DEBUG] "+format, v...)
	}
}
func (l *LeveledLogger) Info(v ...interface{}) {
	if l.level <= LogInfo {
		l.Logger.Print("[INFO] ", fmt.Sprint(v...))
	}
}
func (l *LeveledLogger) Infof(format string, v ...interface{}) {
	if l.level <= LogInfo {
		l.Logger.Printf("[INFO] "+format, v...)
	}
}
func (l *LeveledLogger) Warn(v ...interface{}) {
	if l.level <= LogWarn {
		l.Logger.Print("[WARN] ", fmt.Sprint(v...))
	}
}
func (l *LeveledLogger) Warnf(format string, v ...interface{}) {
	if l.level <= LogWarn {
		l.Logger.Printf("[WARN] "+format, v...)
	}
}
func (l *LeveledLogger) Error(v ...interface{}) {
	if l.level <= LogError {
		l.Logger.Print("[ERROR] ", fmt.Sprint(v...))
	}
}
func (l *LeveledLogger) Errorf(format string, v ...interface{}) {
	if l.level <= LogError {
		l.Logger.Printf("[ERROR] "+format, v...)
	}
}

func loadLines(filename string) ([]string, error) {
	if filename == "" {
		return nil, nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func loadUserAgents(filename string) ([]string, error) {
	if filename == "" {
		return []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		}, nil
	}
	agents, err := loadLines(filename)
	if err != nil {
		return nil, err
	}
	if len(agents) == 0 {
		return nil, fmt.Errorf("no user agents found in %s", filename)
	}
	return agents, nil
}

func loadHeadersFromFile(filename string) ([]string, error) {
	if filename == "" {
		return nil, nil
	}
	return loadLines(filename)
}

func parseStatusList(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	var statuses []int
	for _, p := range parts {
		code, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid status code %q: %w", p, err)
		}
		statuses = append(statuses, code)
	}
	return statuses, nil
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

type RateLimiter struct {
	rate   float64
	burst  int
	tokens float64
	mu     sync.Mutex
	last   time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	if rate <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = int(rate)
		if burst < 1 {
			burst = 1
		}
	}
	return &RateLimiter{
		rate:   rate,
		burst:  burst,
		tokens: float64(burst),
		last:   time.Now(),
	}
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl == nil {
		return nil
	}
	rl.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}
	rl.last = now

	if rl.tokens >= 1 {
		rl.tokens--
		rl.mu.Unlock()
		return nil
	}

	need := (1 - rl.tokens) / rl.rate * float64(time.Second)
	rl.mu.Unlock()

	select {
	case <-time.After(time.Duration(need)):
	case <-ctx.Done():
		return ctx.Err()
	}

	rl.mu.Lock()
	rl.tokens--
	rl.mu.Unlock()
	return nil
}

type ProxyManager struct {
	proxies        []string
	index          uint32
	dead           map[string]int
	failThreshold  int
	mu             sync.Mutex
	perProxyRL     map[string]*RateLimiter
}

func NewProxyManager(proxies []string, perProxyRate float64, failThreshold int) *ProxyManager {
	pm := &ProxyManager{
		proxies:       proxies,
		dead:          make(map[string]int),
		failThreshold: failThreshold,
		perProxyRL:    make(map[string]*RateLimiter),
	}
	if perProxyRate > 0 && len(proxies) > 0 {
		burst := int(perProxyRate)
		if burst < 1 {
			burst = 1
		}
		for _, p := range proxies {
			pm.perProxyRL[p] = NewRateLimiter(perProxyRate, burst)
		}
	}
	return pm
}

func (pm *ProxyManager) Next(ctx context.Context) (string, *RateLimiter, error) {
	if len(pm.proxies) == 0 {
		return "", nil, nil
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for i := 0; i < len(pm.proxies); i++ {
		idx := atomic.AddUint32(&pm.index, 1) - 1
		proxy := pm.proxies[idx%uint32(len(pm.proxies))]
		if pm.dead[proxy] >= pm.failThreshold {
			continue
		}
		return proxy, pm.perProxyRL[proxy], nil
	}
	for p := range pm.dead {
		delete(pm.dead, p)
	}
	proxy := pm.proxies[0]
	return proxy, pm.perProxyRL[proxy], nil
}

func (pm *ProxyManager) MarkDead(proxy string) {
	if proxy == "" {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.dead[proxy]++
}

func (pm *ProxyManager) MarkAlive(proxy string) {
	if proxy == "" {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.dead, proxy)
}

type Result struct {
	Username     string        `json:"username"`
	Available    bool          `json:"available"`
	StatusCode   int           `json:"status_code,omitempty"`
	ResponseTime time.Duration `json:"response_time,omitempty"`
	Error        string        `json:"error,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
}

type customTransport struct {
	base http.RoundTripper
	pm   *ProxyManager
}

func (ct *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, _ := req.Context().Value("proxy").(string)
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			transport := ct.base.(*http.Transport).Clone()
			transport.Proxy = http.ProxyURL(u)
			return transport.RoundTrip(req)
		}
	}
	return ct.base.RoundTrip(req)
}

type Checker struct {
	config     *Config
	client     *http.Client
	userAgents []string
	headers    []string
	logger     *LeveledLogger
	rlGlobal   *RateLimiter
	pm         *ProxyManager
	re         *regexp.Regexp
}

func NewChecker(cfg *Config, logger *LeveledLogger) (*Checker, error) {
	uas, err := loadUserAgents(cfg.UAFile)
	if err != nil {
		return nil, fmt.Errorf("load user agents: %w", err)
	}
	headers, err := loadHeadersFromFile(cfg.HeaderFile)
	if err != nil {
		return nil, fmt.Errorf("load headers: %w", err)
	}
	headers = append(headers, cfg.Headers...)

	proxies, err := loadProxies(cfg.Proxy, cfg.ProxyFile)
	if err != nil {
		return nil, fmt.Errorf("load proxies: %w", err)
	}
	pm := NewProxyManager(proxies, cfg.PerProxyRateLimit, 3)
	rl := NewRateLimiter(cfg.RateLimit, cfg.RateLimitBurst)

	transport := &http.Transport{
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConns,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLSInsecure,
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	custom := &customTransport{
		base: transport,
		pm:   pm,
	}

	client := &http.Client{
		Timeout:   cfg.RequestTimeout,
		Transport: custom,
	}

	var re *regexp.Regexp
	if cfg.AvailableRegex != "" {
		re, err = regexp.Compile(cfg.AvailableRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
	}

	return &Checker{
		config:     cfg,
		client:     client,
		userAgents: uas,
		headers:    headers,
		logger:     logger,
		rlGlobal:   rl,
		pm:         pm,
		re:         re,
	}, nil
}

func loadProxies(proxy, proxyFile string) ([]string, error) {
	var proxies []string
	if proxy != "" {
		proxies = append(proxies, proxy)
	}
	if proxyFile != "" {
		fileProxies, err := loadLines(proxyFile)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, fileProxies...)
	}
	return proxies, nil
}

func (c *Checker) Check(ctx context.Context, username string) (Result, error) {
	result := Result{
		Username:  username,
		Timestamp: time.Now(),
	}

	urlStr := fmt.Sprintf(c.config.BaseURL, username)
	var bodyReader io.Reader
	if c.config.Method == "POST" || c.config.Method == "PUT" {
		body := fmt.Sprintf(c.config.RequestBody, username)
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, c.config.Method, urlStr, bodyReader)
	if err != nil {
		result.Error = fmt.Sprintf("create request: %v", err)
		return result, err
	}

	ua := c.userAgents[rand.Intn(len(c.userAgents))]
	req.Header.Set("User-Agent", ua)

	for _, h := range c.headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if c.config.BasicAuth != "" {
		parts := strings.SplitN(c.config.BasicAuth, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}
	if c.config.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.BearerToken)
	}
	for _, cookieStr := range c.config.Cookies {
		parts := strings.SplitN(cookieStr, "=", 2)
		if len(parts) == 2 {
			req.AddCookie(&http.Cookie{Name: parts[0], Value: parts[1]})
		}
	}

	proxy, proxyRL, err := c.pm.Next(ctx)
	if err == nil && proxy != "" {
		req = req.WithContext(context.WithValue(req.Context(), "proxy", proxy))
		if proxyRL != nil {
			if err := proxyRL.Wait(ctx); err != nil {
				return result, err
			}
		}
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	result.ResponseTime = time.Since(start)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		if proxy != "" {
			c.pm.MarkDead(proxy)
		}
		return result, err
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		result.Error = fmt.Sprintf("read body: %v", err)
		return result, err
	}
	bodyStr := string(body)

	available := false
	taken := false

	if len(c.config.AvailableStatuses) > 0 && containsInt(c.config.AvailableStatuses, resp.StatusCode) {
		available = true
	}
	if len(c.config.TakenStatuses) > 0 && containsInt(c.config.TakenStatuses, resp.StatusCode) {
		taken = true
	}

	if c.config.AvailableBody != "" && strings.Contains(bodyStr, c.config.AvailableBody) {
		available = true
	}
	if c.re != nil && c.re.MatchString(bodyStr) {
		available = true
	}

	if proxy != "" {
		c.pm.MarkAlive(proxy)
	}

	result.Available = available
	if !available && !taken && resp.StatusCode >= 400 {
		result.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
	return result, nil
}

type Generator struct {
	config *Config
	logger *LeveledLogger
	seen   *sync.Map
	rng    *rand.Rand
}

func NewGenerator(cfg *Config, logger *LeveledLogger) *Generator {
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &Generator{
		config: cfg,
		logger: logger,
		seen:   &sync.Map{},
		rng:    rand.New(rand.NewSource(seed)),
	}
}

func (g *Generator) generateUsername() string {
	pool := "abcdefghijklmnopqrstuvwxyz"
	switch g.config.Mode {
	case "letters":
		pool = "abcdefghijklmnopqrstuvwxyz"
	case "alnum":
		pool = "abcdefghijklmnopqrstuvwxyz0123456789"
	case "digits":
		pool = "0123456789"
	default:
		if g.config.Mode != "" {
			pool = g.config.Mode
		}
	}
	length := g.config.Length
	prefix := g.config.Prefix
	suffix := g.config.Suffix
	bodyLen := length - len(prefix) - len(suffix)
	if bodyLen < 1 {
		bodyLen = 1
	}
	sb := strings.Builder{}
	sb.Grow(length)
	sb.WriteString(prefix)
	for i := 0; i < bodyLen; i++ {
		sb.WriteByte(pool[g.rng.Intn(len(pool))])
	}
	sb.WriteString(suffix)
	return sb.String()
}

func (g *Generator) UniqueUsername() string {
	for {
		name := g.generateUsername()
		if _, loaded := g.seen.LoadOrStore(name, struct{}{}); !loaded {
			return name
		}
	}
}

func (g *Generator) Generate(ctx context.Context, jobs chan<- string, resume *ResumeManager) error {
	defer close(jobs)

	if g.config.CheckFile != "" {
		file, err := os.Open(g.config.CheckFile)
		if err != nil {
			return err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if resume != nil && resume.IsSeen(line) {
				continue
			}
			select {
			case jobs <- line:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return scanner.Err()
	}

	total := g.config.TotalChecks
	for i := 0; total == -1 || i < total; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			name := g.UniqueUsername()
			if resume != nil && resume.IsSeen(name) {
				if total != -1 {
					i--
				}
				continue
			}
			select {
			case jobs <- name:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

type ResumeManager struct {
	file *os.File
	mu   sync.Mutex
	seen *sync.Map
	buf  *bufio.Writer
}

func NewResumeManager(filename string) (*ResumeManager, error) {
	rm := &ResumeManager{
		seen: &sync.Map{},
	}
	if filename == "" {
		return rm, nil
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	rm.file = f
	rm.buf = bufio.NewWriter(f)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			rm.seen.Store(line, struct{}{})
		}
	}
	return rm, scanner.Err()
}

func (rm *ResumeManager) IsSeen(username string) bool {
	_, ok := rm.seen.Load(username)
	return ok
}

func (rm *ResumeManager) Add(username string) error {
	if rm.file == nil {
		return nil
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if _, err := rm.buf.WriteString(username + "\n"); err != nil {
		return err
	}
	rm.seen.Store(username, struct{}{})
	return nil
}

func (rm *ResumeManager) Flush() error {
	if rm.buf == nil {
		return nil
	}
	return rm.buf.Flush()
}

func (rm *ResumeManager) Close() error {
	if rm.file == nil {
		return nil
	}
	if err := rm.Flush(); err != nil {
		return err
	}
	return rm.file.Close()
}

type OutputManager struct {
	format    string
	file      *os.File
	allFile   *os.File
	writer    *bufio.Writer
	allWriter *bufio.Writer
	csvWriter *csv.Writer
	jsonEnc   *json.Encoder
	mu        sync.Mutex
	firstJSON bool
	logger    *LeveledLogger
}

func NewOutputManager(cfg *Config, logger *LeveledLogger) (*OutputManager, error) {
	om := &OutputManager{
		format:    cfg.OutputFormat,
		firstJSON: true,
		logger:    logger,
	}
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return nil, err
		}
		om.file = f
		om.writer = bufio.NewWriter(f)
		if cfg.OutputFormat == "json" {
			om.jsonEnc = json.NewEncoder(om.writer)
			om.writer.WriteString("[\n")
		} else if cfg.OutputFormat == "csv" {
			om.csvWriter = csv.NewWriter(om.writer)
			om.csvWriter.Write([]string{"username", "available", "status_code", "error", "timestamp"})
		}
	}
	if cfg.OutputAllFile != "" {
		f, err := os.Create(cfg.OutputAllFile)
		if err != nil {
			return nil, err
		}
		om.allFile = f
		om.allWriter = bufio.NewWriter(f)
		if _, err := om.allWriter.WriteString("username,available,status_code,error,timestamp\n"); err != nil {
			return nil, err
		}
	}
	return om, nil
}

func (om *OutputManager) WriteResult(r Result) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.file != nil {
		switch om.format {
		case "plain":
			if r.Available && r.Error == "" {
				if _, err := om.writer.WriteString(r.Username + "\n"); err != nil {
					return err
				}
			}
		case "json":
			if !om.firstJSON {
				om.writer.WriteString(",\n")
			}
			om.firstJSON = false
			if err := om.jsonEnc.Encode(r); err != nil {
				return err
			}
		case "csv":
			record := []string{
				r.Username,
				strconv.FormatBool(r.Available),
				strconv.Itoa(r.StatusCode),
				r.Error,
				r.Timestamp.Format(time.RFC3339),
			}
			if err := om.csvWriter.Write(record); err != nil {
				return err
			}
			om.csvWriter.Flush()
		case "ndjson":
			data, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err := om.writer.Write(append(data, '\n')); err != nil {
				return err
			}
		}
		if err := om.writer.Flush(); err != nil {
			return err
		}
	}

	if om.allFile != nil {
		line := fmt.Sprintf("%s,%t,%d,%s,%s\n",
			r.Username, r.Available, r.StatusCode, r.Error, r.Timestamp.Format(time.RFC3339))
		if _, err := om.allWriter.WriteString(line); err != nil {
			return err
		}
		if err := om.allWriter.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (om *OutputManager) Close() error {
	if om.file != nil {
		if om.format == "json" {
			om.writer.WriteString("\n]\n")
			om.writer.Flush()
		}
		if err := om.file.Close(); err != nil {
			return err
		}
	}
	if om.allFile != nil {
		if err := om.allFile.Close(); err != nil {
			return err
		}
	}
	return nil
}

func sendWebhook(ctx context.Context, url string, username string) error {
	if url == "" {
		return nil
	}
	payload := map[string]string{"username": username, "available": "true"}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

type Stats struct {
	Checked   int64
	Available int64
	Taken     int64
	Errors    int64
	Start     time.Time
}

func (s *Stats) AddChecked()   { atomic.AddInt64(&s.Checked, 1) }
func (s *Stats) AddAvailable() { atomic.AddInt64(&s.Available, 1) }
func (s *Stats) AddTaken()     { atomic.AddInt64(&s.Taken, 1) }
func (s *Stats) AddError()     { atomic.AddInt64(&s.Errors, 1) }

func (s *Stats) Snapshot() (checked, available, taken, errors int64) {
	return atomic.LoadInt64(&s.Checked),
		atomic.LoadInt64(&s.Available),
		atomic.LoadInt64(&s.Taken),
		atomic.LoadInt64(&s.Errors)
}

func main() {
	var (
		baseURL           = flag.String("base-url", defaultConfig.BaseURL, "")
		method            = flag.String("method", defaultConfig.Method, "")
		requestBody       = flag.String("request-body", defaultConfig.RequestBody, "")
		mode              = flag.String("mode", defaultConfig.Mode, "")
		length            = flag.Int("length", defaultConfig.Length, "")
		prefix            = flag.String("prefix", defaultConfig.Prefix, "")
		suffix            = flag.String("suffix", defaultConfig.Suffix, "")
		seed              = flag.Int64("seed", defaultConfig.Seed, "")
		total             = flag.Int("total", defaultConfig.TotalChecks, "")
		threads           = flag.Int("threads", defaultConfig.ThreadCount, "")
		outputFile        = flag.String("output", defaultConfig.OutputFile, "")
		outputAllFile     = flag.String("output-all", defaultConfig.OutputAllFile, "")
		outputFormat      = flag.String("output-format", defaultConfig.OutputFormat, "")
		requestTimeout    = flag.Duration("request-timeout", defaultConfig.RequestTimeout, "")
		overallTimeout    = flag.Duration("timeout", defaultConfig.OverallTimeout, "")
		uaFile            = flag.String("ua-file", defaultConfig.UAFile, "")
		delay             = flag.Duration("delay", defaultConfig.Delay, "")
		delayJitter       = flag.Duration("delay-jitter", defaultConfig.DelayJitter, "")
		retries           = flag.Int("retries", defaultConfig.Retries, "")
		maxBackoff        = flag.Duration("max-backoff", defaultConfig.MaxBackoff, "")
		proxy             = flag.String("proxy", defaultConfig.Proxy, "")
		proxyFile         = flag.String("proxy-file", defaultConfig.ProxyFile, "")
		proxyType         = flag.String("proxy-type", defaultConfig.ProxyType, "")
		quiet             = flag.Bool("quiet", defaultConfig.Quiet, "")
		verbose           = flag.Bool("verbose", defaultConfig.Verbose, "")
		logLevel          = flag.String("log-level", defaultConfig.LogLevel, "")
		logFile           = flag.String("log-file", defaultConfig.LogFile, "")
		checkFile         = flag.String("check-file", defaultConfig.CheckFile, "")
		resumeFile        = flag.String("resume-file", defaultConfig.ResumeFile, "")
		statsInterval     = flag.Duration("stats-interval", defaultConfig.StatsInterval, "")
		rateLimit         = flag.Float64("rate", defaultConfig.RateLimit, "")
		rateLimitBurst    = flag.Int("rate-burst", defaultConfig.RateLimitBurst, "")
		perProxyRate      = flag.Float64("per-proxy-rate", defaultConfig.PerProxyRateLimit, "")
		headerFile        = flag.String("header-file", defaultConfig.HeaderFile, "")
		availableStatuses = flag.String("available-status", "404", "")
		takenStatuses     = flag.String("taken-status", "200", "")
		retryStatuses     = flag.String("retry-status", "429,500,502,503,504", "")
		availableBody     = flag.String("available-body", defaultConfig.AvailableBody, "")
		availableRegex    = flag.String("available-regex", defaultConfig.AvailableRegex, "")
		webhookURL        = flag.String("webhook", defaultConfig.WebhookURL, "")
		dryRun            = flag.Bool("dry-run", defaultConfig.DryRun, "")
		tlsInsecure       = flag.Bool("tls-insecure", defaultConfig.TLSInsecure, "")
		basicAuth         = flag.String("basic-auth", defaultConfig.BasicAuth, "")
		bearerToken       = flag.String("bearer-token", defaultConfig.BearerToken, "")
		maxIdleConns      = flag.Int("max-idle-conns", defaultConfig.MaxIdleConns, "")
		idleConnTimeout   = flag.Duration("idle-conn-timeout", defaultConfig.IdleConnTimeout, "")
	)
	flag.Parse()

	cfg := &Config{
		BaseURL:           *baseURL,
		Method:            *method,
		RequestBody:       *requestBody,
		Mode:              *mode,
		Length:            *length,
		Prefix:            *prefix,
		Suffix:            *suffix,
		Seed:              *seed,
		TotalChecks:       *total,
		ThreadCount:       *threads,
		OutputFile:        *outputFile,
		OutputAllFile:     *outputAllFile,
		OutputFormat:      *outputFormat,
		RequestTimeout:    *requestTimeout,
		OverallTimeout:    *overallTimeout,
		UAFile:            *uaFile,
		Delay:             *delay,
		DelayJitter:       *delayJitter,
		Retries:           *retries,
		MaxBackoff:        *maxBackoff,
		Proxy:             *proxy,
		ProxyFile:         *proxyFile,
		ProxyType:         *proxyType,
		Quiet:             *quiet,
		Verbose:           *verbose,
		LogLevel:          *logLevel,
		LogFile:           *logFile,
		CheckFile:         *checkFile,
		ResumeFile:        *resumeFile,
		StatsInterval:     *statsInterval,
		RateLimit:         *rateLimit,
		RateLimitBurst:    *rateLimitBurst,
		PerProxyRateLimit: *perProxyRate,
		HeaderFile:        *headerFile,
		AvailableBody:     *availableBody,
		AvailableRegex:    *availableRegex,
		WebhookURL:        *webhookURL,
		DryRun:            *dryRun,
		TLSInsecure:       *tlsInsecure,
		BasicAuth:         *basicAuth,
		BearerToken:       *bearerToken,
		MaxIdleConns:      *maxIdleConns,
		IdleConnTimeout:   *idleConnTimeout,
	}

	av, err := parseStatusList(*availableStatuses)
	if err != nil {
		log.Fatalf("invalid available-status: %v", err)
	}
	cfg.AvailableStatuses = av
	tk, err := parseStatusList(*takenStatuses)
	if err != nil {
		log.Fatalf("invalid taken-status: %v", err)
	}
	cfg.TakenStatuses = tk
	rt, err := parseStatusList(*retryStatuses)
	if err != nil {
		log.Fatalf("invalid retry-status: %v", err)
	}
	cfg.RetryStatuses = rt

	logOutput := os.Stderr
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("cannot open log file: %v", err)
		}
		defer f.Close()
		logOutput = f
	}
	logger := NewLeveledLogger(logOutput, cfg.LogLevel)

	logger.Infof("starting username checker (pid %d)", os.Getpid())

	resume, err := NewResumeManager(cfg.ResumeFile)
	if err != nil {
		logger.Fatalf("resume manager error: %v", err)
	}
	defer resume.Close()

	var checker *Checker
	if !cfg.DryRun {
		checker, err = NewChecker(cfg, logger)
		if err != nil {
			logger.Fatalf("failed to create checker: %v", err)
		}
	}

	generator := NewGenerator(cfg, logger)

	output, err := NewOutputManager(cfg, logger)
	if err != nil {
		logger.Fatalf("output manager error: %v", err)
	}
	defer output.Close()

	stats := &Stats{Start: time.Now()}

	ctx, cancel := context.WithCancel(context.Background())
	if cfg.OverallTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.OverallTimeout)
	}
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("received interrupt, shutting down gracefully...")
		cancel()
	}()

	jobs := make(chan string, cfg.ThreadCount*2)
	results := make(chan Result, cfg.ThreadCount*2)

	var wg sync.WaitGroup
	if !cfg.DryRun {
		for i := 0; i < cfg.ThreadCount; i++ {
			wg.Add(1)
			go worker(ctx, jobs, results, checker, cfg, logger, stats, &wg)
		}
	} else {
		go func() {
			defer close(results)
			for {
				select {
				case <-ctx.Done():
					return
				case username, ok := <-jobs:
					if !ok {
						return
					}
					results <- Result{
						Username:  username,
						Available: true,
						Timestamp: time.Now(),
					}
				}
			}
		}()
	}

	go func() {
		if err := generator.Generate(ctx, jobs, resume); err != nil && err != context.Canceled {
			logger.Errorf("generator error: %v", err)
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	if err := processResults(ctx, results, output, stats, logger, cfg, resume); err != nil && err != context.Canceled {
		logger.Fatalf("error processing results: %v", err)
	}

	logger.Info("done.")
	printFinalStats(stats, logger)
}

func worker(ctx context.Context, jobs <-chan string, results chan<- Result,
	checker *Checker, cfg *Config, logger *LeveledLogger, stats *Stats, wg *sync.WaitGroup) {
	defer wg.Done()

	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(rand.Int())))

	for {
		select {
		case <-ctx.Done():
			return
		case username, ok := <-jobs:
			if !ok {
				return
			}
			if checker.rlGlobal != nil {
				if err := checker.rlGlobal.Wait(ctx); err != nil {
					return
				}
			}

			result, err := checker.Check(ctx, username)
			if err != nil && result.Error == "" {
				result.Error = err.Error()
			}

			stats.AddChecked()
			if result.Available {
				stats.AddAvailable()
				if !cfg.Quiet {
					logger.Infof("[+] %s", username)
				}
			} else if result.Error != "" {
				stats.AddError()
				if !cfg.Quiet {
					logger.Warnf("[!] %s: %s", username, result.Error)
				}
			} else {
				stats.AddTaken()
				if !cfg.Quiet {
					logger.Infof("[-] %s", username)
				}
			}

			select {
			case results <- result:
			case <-ctx.Done():
				return
			}

			if cfg.Delay > 0 {
				delay := cfg.Delay
				if cfg.DelayJitter > 0 {
					delay += time.Duration(rng.Int63n(int64(cfg.DelayJitter)))
				}
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func processResults(ctx context.Context, results <-chan Result, output *OutputManager,
	stats *Stats, logger *LeveledLogger, cfg *Config, resume *ResumeManager) error {

	ticker := time.NewTicker(cfg.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case result, ok := <-results:
			if !ok {
				return nil
			}
			if result.Available && result.Error == "" {
				if err := output.WriteResult(result); err != nil {
					logger.Errorf("output write error: %v", err)
				}
				if cfg.WebhookURL != "" {
					go func() {
						if err := sendWebhook(ctx, cfg.WebhookURL, result.Username); err != nil {
							logger.Warnf("webhook error: %v", err)
						}
					}()
				}
			}
			if cfg.OutputAllFile != "" {
				if err := output.WriteResult(result); err != nil {
					logger.Errorf("all-output write error: %v", err)
				}
			}
			if err := resume.Add(result.Username); err != nil {
				logger.Errorf("resume add error: %v", err)
			}

		case <-ticker.C:
			if cfg.StatsInterval > 0 {
				printPeriodicStats(stats, logger)
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func printPeriodicStats(stats *Stats, logger *LeveledLogger) {
	checked, avail, taken, errs := stats.Snapshot()
	elapsed := time.Since(stats.Start)
	rate := float64(checked) / elapsed.Seconds()
	logger.Infof("Checked: %d | Avail: %d | Taken: %d | Errors: %d | Rate: %.2f/s",
		checked, avail, taken, errs, rate)
}

func printFinalStats(stats *Stats, logger *LeveledLogger) {
	checked, avail, taken, errs := stats.Snapshot()
	elapsed := time.Since(stats.Start)
	rate := float64(checked) / elapsed.Seconds()
	logger.Infof("=== FINAL ===")
	logger.Infof("Total checked: %d", checked)
	logger.Infof("Available: %d", avail)
	logger.Infof("Taken: %d", taken)
	logger.Infof("Errors: %d", errs)
	logger.Infof("Elapsed: %s", elapsed.Round(time.Millisecond))
	if checked > 0 {
		logger.Infof("Rate: %.2f checks/s", rate)
	}
}
