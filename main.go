package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cReset  = "\033[0m"
	cRed    = "\033[91m"
	cGreen  = "\033[92m"
	cYellow = "\033[93m"
	cCyan   = "\033[96m"
	cGray   = "\033[90m"
	cBold   = "\033[1m"
	cPurple = "\033[95m"
)

type ColorHandler struct {
	level slog.Level
}

func (h *ColorHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *ColorHandler) Handle(_ context.Context, r slog.Record) error {
	t := r.Time.Format("15:04:05")
	var icon, lc string
	switch {
	case r.Level >= slog.LevelError:
		icon, lc = "✗", cRed
	case r.Level >= slog.LevelWarn:
		icon, lc = "⚠", cYellow
	default:
		icon, lc = "✓", cGreen
	}

	var parts []string
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "id":
			parts = append(parts, fmt.Sprintf("%s#%v%s", cPurple, a.Value, cReset))
		case "key":
			parts = append(parts, fmt.Sprintf("%skey%s=%v", cCyan, cReset, a.Value))
		case "code":
			parts = append(parts, fmt.Sprintf("%scode%s=%v", cCyan, cReset, a.Value))
		case "err":
			parts = append(parts, fmt.Sprintf("%s%v%s", cRed, a.Value, cReset))
		default:
			parts = append(parts, fmt.Sprintf("%s%s%s=%v", cGray, a.Key, cReset, a.Value))
		}
		return true
	})

	attrs := ""
	if len(parts) > 0 {
		attrs = " " + strings.Join(parts, " ")
	}

	fmt.Fprintf(os.Stderr, "%s%s%s %s%s%s %s%s\n",
		cGray, t, cReset,
		lc, icon, cReset,
		r.Message, attrs)
	return nil
}

func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *ColorHandler) WithGroup(_ string) slog.Handler          { return h }

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        300,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

const (
	baseURL         = "https://api.airforce"
	signupURL       = baseURL + "/auth/signup"
	meURL           = baseURL + "/api/me"
	referralURL     = baseURL + "/api/referral/code"
	siteKey         = "0x4AAAAAACY9xSVz3RBFYucU"
	siteURL         = "https://api.airforce"
	maxReferralUses = 3
	apiKeyFile      = "api_keys.txt"
	referralFile    = "code.json"
	accountFile     = "accounts.txt"
)

var (
	usernameChars = []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	passwordChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+")
)

type ReferralCode struct {
	Code string `json:"code"`
	Uses int    `json:"uses"`
}

type ReferralStore struct {
	mu    sync.Mutex
	codes []ReferralCode
	path  string
}

type SignupRequest struct {
	Username     string  `json:"username"`
	Password     string  `json:"password"`
	ReferralCode *string `json:"referral_code"`
	CaptchaToken string  `json:"captcha_token"`
}

type MeResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	APIKey   string `json:"api_key"`
	Plan     string `json:"plan"`
}

type ReferralResponse struct {
	Code string `json:"referral_code"`
}
type CaptchaTaskResponse struct {
	TaskID string `json:"taskId"`
}

/* CaptchaResultResponse 验证码结果响应 */
type CaptchaResultResponse struct {
	Solution struct {
		Token string `json:"token"`
	} `json:"solution"`
}

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"

func newReferralStore(dataDir string) *ReferralStore {
	store := &ReferralStore{
		path: filepath.Join(dataDir, referralFile),
	}
	store.load()
	return store
}

func (s *ReferralStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.codes = []ReferralCode{}
		return
	}
	if err := json.Unmarshal(data, &s.codes); err != nil {
		slog.Warn("解析邀请码文件失败", "err", err)
		s.codes = []ReferralCode{}
	}
}

func (s *ReferralStore) save() error {
	data, err := json.MarshalIndent(s.codes, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化邀请码失败: %w", err)
	}
	return os.WriteFile(s.path, data, 0644)
}

func (s *ReferralStore) getAvailable() *string {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.codes {
		if s.codes[i].Uses < maxReferralUses {
			s.codes[i].Uses++
			_ = s.save()
			code := s.codes[i].Code
			return &code
		}
	}
	return nil
}

func (s *ReferralStore) add(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.codes {
		if c.Code == code {
			return nil
		}
	}

	s.codes = append(s.codes, ReferralCode{Code: code, Uses: 0})
	return s.save()
}

func randomString(charset []byte, length int) string {
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

func generateUsername() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(5))
	length := int(n.Int64()) + 8
	return randomString(usernameChars, length)
}

func generatePassword() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(7))
	length := int(n.Int64()) + 12
	return randomString(passwordChars, length)
}

func solveCaptcha(solverURL string) (string, error) {
	taskURL := fmt.Sprintf("%s/turnstile?url=%s&sitekey=%s",
		solverURL,
		url.QueryEscape(siteURL),
		url.QueryEscape(siteKey),
	)

	resp, err := httpClient.Get(taskURL)
	if err != nil {
		return "", fmt.Errorf("创建验证码任务失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取任务响应失败: %w", err)
	}
	var taskResp CaptchaTaskResponse
	if err := json.Unmarshal(body, &taskResp); err != nil {
		return "", fmt.Errorf("解析任务响应失败: %w, body: %s", err, string(body))
	}

	if taskResp.TaskID == "" {
		return "", fmt.Errorf("任务ID为空, 响应: %s", string(body))
	}
	time.Sleep(5 * time.Second)
	for i := 0; i < 60; i++ {
		resultURL := fmt.Sprintf("%s/result?id=%s", solverURL, taskResp.TaskID)
		resp, err := httpClient.Get(resultURL)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		var result CaptchaResultResponse
		if err := json.Unmarshal(body, &result); err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		token := result.Solution.Token
		if token != "" && token != "CAPTCHA_FAIL" {
			return token, nil
		}
		if token == "CAPTCHA_FAIL" {
			return "", fmt.Errorf("验证码解决失败")
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("验证码获取超时")
}
func setCommonHeaders(req *http.Request) {
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("DNT", "1")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Ch-Ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", userAgent)
}

/* signup 注册新账号，返回 JWT token */
func signup(username, password, captchaToken string, referralCode *string) (string, error) {
	reqBody := SignupRequest{
		Username:     username,
		Password:     password,
		ReferralCode: referralCode,
		CaptchaToken: captchaToken,
	}

	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("序列化注册请求失败: %w", err)
	}

	req, err := http.NewRequest("POST", signupURL, bytes.NewReader(bodyData))
	if err != nil {
		return "", fmt.Errorf("创建注册请求失败: %w", err)
	}

	setCommonHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", baseURL+"/signup/")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("注册请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取注册响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("注册失败, 状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	/* 响应体就是 JWT token */
	jwt := strings.TrimSpace(string(body))
	/* 如果响应是 JSON 格式，尝试提取 token 字段 */
	if strings.HasPrefix(jwt, "{") {
		var tokenResp map[string]interface{}
		if err := json.Unmarshal(body, &tokenResp); err == nil {
			if t, ok := tokenResp["token"].(string); ok {
				jwt = t
			} else if t, ok := tokenResp["access_token"].(string); ok {
				jwt = t
			}
		}
	}
	jwt = strings.Trim(jwt, "\"")

	return jwt, nil
}

func getUserInfo(jwt string) (*MeResponse, error) {
	req, err := http.NewRequest("GET", meURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建用户信息请求失败: %w", err)
	}

	setCommonHeaders(req)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Referer", baseURL+"/signup/")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取用户信息失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取用户信息响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取用户信息失败, 状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var me MeResponse
	if err := json.Unmarshal(body, &me); err != nil {
		return nil, fmt.Errorf("解析用户信息失败: %w", err)
	}

	return &me, nil
}

var modelsToEnable = []string{
	"claude-sonnet-4.6-uncensored",
	"hermes-4-405b",
	"hermes-4-70b",
	"chatgpt-4o-latest",
	"gpt-5.1-chat",
	"gpt-5.2-chat",
	"gpt-5.2-codex",
	"gpt-5.3-codex",
	"gemini-3-flash",
	"claude-sonnet-4.5-uncensored",
	"claude-opus-4.5-uncensored",
	"claude-opus-4.6-uncensored",
	"gemini-3-pro",
	"nano-banana-pro",
	"seedream-4.5",
	"deepseek-r1",
	"grok-4.1-fast-non-reasoning",
	"grok-4.1-fast-reasoning",
	"grok-4-thinking",
	"grok-4.1-thinking",
	"grok-4.1-expert",
	"mistral-small-creative",
	"gpt-image-1.5",
	"sora-2",
	"veo-3.1-fast",
}

func toggleModel(jwt, model string) error {
	toggleURL := fmt.Sprintf("%s/api/models/%s/toggle", baseURL, model)
	req, err := http.NewRequest("POST", toggleURL, nil)
	if err != nil {
		return err
	}

	setCommonHeaders(req)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", baseURL+"/dashboard/")
	req.Header.Set("Content-Length", "0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("状态码: %d", resp.StatusCode)
	}
	return nil
}

func enableModels(jwt string, index int) {
	var wg sync.WaitGroup
	var failCount atomic.Int32

	for _, m := range modelsToEnable {
		wg.Add(1)
		go func(model string) {
			defer wg.Done()
			if err := toggleModel(jwt, model); err != nil {
				failCount.Add(1)
			}
		}(m)
	}

	wg.Wait()
	if f := failCount.Load(); f > 0 {
		slog.Warn("部分模型启用失败", "id", index, "fail", f)
	} else {
	}
}

func getReferralCode(jwt string) (string, error) {
	req, err := http.NewRequest("GET", referralURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	setCommonHeaders(req)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Referer", baseURL+"/dashboard/")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("状态码: %d", resp.StatusCode)
	}

	var referral ReferralResponse
	if err := json.Unmarshal(body, &referral); err != nil {
		return "", fmt.Errorf("解析失败: %w", err)
	}

	return referral.Code, nil
}

func saveAPIKey(dataDir, apiKey string) error {
	f, err := os.OpenFile(filepath.Join(dataDir, apiKeyFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开 api_key 文件失败: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintln(f, apiKey)
	return err
}

func saveAccount(dataDir, username, password, apiKey string) error {
	f, err := os.OpenFile(filepath.Join(dataDir, accountFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开账号文件失败: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s|%s|%s\n", username, password, apiKey)
	return err
}

type CaptchaPool struct {
	tokens     chan string
	solverURLs []string
	stopCh     chan struct{}
}

func newCaptchaPool(solverURLs []string, workers int) *CaptchaPool {
	p := &CaptchaPool{
		tokens:     make(chan string, workers*3),
		solverURLs: solverURLs,
		stopCh:     make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		go p.worker(solverURLs[i%len(solverURLs)])
	}
	return p
}

func (p *CaptchaPool) worker(solverURL string) {
	for {
		select {
		case <-p.stopCh:
			return
		default:
		}
		token, err := solveCaptcha(solverURL)
		if err != nil {
			continue
		}
		select {
		case p.tokens <- token:
		case <-p.stopCh:
			return
		}
	}
}

func (p *CaptchaPool) get() string {
	return <-p.tokens
}

func (p *CaptchaPool) stop() {
	close(p.stopCh)
}

func doSignup(pool *CaptchaPool, store *ReferralStore) (jwt, username, password string, err error) {
	referralCode := store.getAvailable()
	captchaToken := pool.get()
	username = generateUsername()
	password = generatePassword()
	jwt, err = signup(username, password, captchaToken, referralCode)
	return
}

func doPostSignup(jwt, username, password, dataDir string, store *ReferralStore, index int) {
	var (
		meResp      *MeResponse
		newReferral string
		meErr       error
		refErr      error
		wg          sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		meResp, meErr = getUserInfo(jwt)
	}()
	go func() {
		defer wg.Done()
		newReferral, refErr = getReferralCode(jwt)
	}()
	go func() {
		defer wg.Done()
		enableModels(jwt, index)
	}()
	wg.Wait()

	if meErr != nil {
		slog.Error("获取用户信息失败", "id", index, "err", meErr)
		return
	}
	slog.Info("完成", "id", index, "key", meResp.APIKey[:20]+"...")
	_ = saveAPIKey(dataDir, meResp.APIKey)
	_ = saveAccount(dataDir, username, password, meResp.APIKey)
	if refErr != nil {
		slog.Warn("邀请码获取失败", "id", index, "err", refErr)
	} else if newReferral != "" {
		_ = store.add(newReferral)
	}
}

func main() {
	count := flag.Int("count", 1, "注册账号数量")
	concurrent := flag.Int("concurrent", 1, "并发数")
	workers := flag.Int("workers", 0, "验证码预解并发数 (默认=concurrent*2)")
	solverURL := flag.String("solver", "http://127.0.0.1:5072", "Turnstile Solver 地址 (多个用逗号分隔)")
	dataDir := flag.String("data", ".", "数据文件保存目录")
	flag.Parse()
	if *workers <= 0 {
		*workers = *concurrent * 2
	}
	slog.SetDefault(slog.New(&ColorHandler{level: slog.LevelDebug}))
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		slog.Error("创建数据目录失败", "err", err)
		os.Exit(1)
	}
	store := newReferralStore(*dataDir)
	solverURLs := strings.Split(*solverURL, ",")
	for i := range solverURLs {
		solverURLs[i] = strings.TrimSpace(solverURLs[i])
	}
	pool := newCaptchaPool(solverURLs, *workers)
	defer pool.stop()
	sem := make(chan struct{}, *concurrent)
	var signupWg, bgWg sync.WaitGroup
	var successCount, failCount atomic.Int32
	for i := 1; i <= *count; i++ {
		signupWg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer signupWg.Done()
			jwt, username, password, err := doSignup(pool, store)
			<-sem
			if err != nil {
				slog.Error("注册失败", "id", idx, "err", err)
				failCount.Add(1)
				return
			}
			successCount.Add(1)
			bgWg.Add(1)
			go func() {
				defer bgWg.Done()
				doPostSignup(jwt, username, password, *dataDir, store, idx)
			}()
		}(i)
	}
	signupWg.Wait()
	bgWg.Wait()
}
