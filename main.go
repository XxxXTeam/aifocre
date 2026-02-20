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
	"os/exec"
	"os/signal"
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

/*
findSolverDir 查找 solver 目录，依次尝试可执行文件同级和当前工作目录。
*/
func findSolverDir() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "solver")
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	if info, err := os.Stat("solver"); err == nil && info.IsDir() {
		return "solver"
	}
	return ""
}

/*
isSolverReachable 检测 solver 是否可连接。
*/
func isSolverReachable(solverURL string) bool {
	u, err := url.Parse(solverURL)
	if err != nil {
		return false
	}
	checkURL := fmt.Sprintf("%s://%s/result?id=health", u.Scheme, u.Host)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(checkURL)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

/*
runCmd 运行命令并将输出打印到 stdout/stderr，返回 error。
*/
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

/* runCmdQuiet 静默执行命令，失败时返回包含 stderr 信息的 error */
func runCmdQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, errBuf.String())
	}
	return nil
}

func installSolverDeps(solverDir string) error {
	uvPath, uvErr := exec.LookPath("uv")
	pipPath, pipErr := exec.LookPath("pip")

	if uvErr != nil && pipErr != nil {
		return fmt.Errorf("未找到 uv 或 pip，请至少安装其中一个\n  uv: https://docs.astral.sh/uv/getting-started/installation/")
	}

	/* 静默安装 Python 依赖，只在失败时报错 */
	if uvErr == nil {
		if err := runCmdQuiet(uvPath, "sync", "--project", solverDir); err != nil {
			slog.Warn("uv sync 失败，尝试 pip", "err", err)
			if pipErr == nil {
				reqFile := filepath.Join(solverDir, "requirements.txt")
				if err := runCmdQuiet(pipPath, "install", "-q", "-r", reqFile); err != nil {
					return fmt.Errorf("pip install 也失败: %w", err)
				}
			} else {
				return fmt.Errorf("uv sync 失败且 pip 不可用: %w", err)
			}
		}
	} else {
		reqFile := filepath.Join(solverDir, "requirements.txt")
		if err := runCmdQuiet(pipPath, "install", "-q", "-r", reqFile); err != nil {
			return fmt.Errorf("pip install 失败: %w", err)
		}
	}

	/* 静默检查/安装 patchright 浏览器 */
	if uvErr == nil {
		if err := runCmdQuiet(uvPath, "run", "--project", solverDir, "patchright", "install", "chromium"); err != nil {
			_ = runCmdQuiet("patchright", "install", "chromium")
		}
	} else {
		_ = runCmdQuiet("patchright", "install", "chromium")
	}

	/* 静默检查/安装 camoufox 浏览器 */
	if uvErr == nil {
		if err := runCmdQuiet(uvPath, "run", "--project", solverDir, "python", "-m", "camoufox", "fetch"); err != nil {
			_ = runCmdQuiet("python", "-m", "camoufox", "fetch")
		}
	} else {
		_ = runCmdQuiet("python", "-m", "camoufox", "fetch")
	}

	return nil
}

/*
startSolver 启动 Turnstile Solver 子进程。
自动安装依赖和浏览器，返回 cleanup 函数。
*/
func startSolver(browsers int, port string) (cleanup func(), err error) {
	solverDir := findSolverDir()
	if solverDir == "" {
		return nil, fmt.Errorf("未找到 solver 目录，请确保 solver/ 在程序同级或当前目录下")
	}

	/* 自动安装依赖和浏览器 */
	if err := installSolverDeps(solverDir); err != nil {
		return nil, err
	}

	/* 构建启动命令：优先 uv run，fallback 到 python */
	var cmd *exec.Cmd
	uvPath, uvErr := exec.LookPath("uv")
	if uvErr == nil {
		args := []string{
			"run", "--project", solverDir,
			"python", "api_solver.py",
			"--thread", fmt.Sprintf("%d", browsers),
			"--host", "127.0.0.1",
			"--browser_type", "camoufox",
			"--port", port,
		}
		cmd = exec.Command(uvPath, args...)
	} else {
		pythonPath := "python"
		if p, err := exec.LookPath("python3"); err == nil {
			pythonPath = p
		}
		cmd = exec.Command(pythonPath,
			"api_solver.py",
			"--thread", fmt.Sprintf("%d", browsers),
			"--host", "127.0.0.1",
			"--browser_type", "camoufox",
			"--port", port,
		)
	}

	/* 设置工作目录为 solver 目录，确保 Python 能找到本地模块 */
	cmd.Dir = solverDir
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8")
	cmd.Stdout = io.Discard

	/* 捕获 stderr 用于诊断启动失败 */
	stderrPipe, pipeErr := cmd.StderrPipe()
	if pipeErr != nil {
		cmd.Stderr = io.Discard
	}

	setSysProcAttr(cmd)

	slog.Info("启动 Solver", "browsers", browsers, "port", port)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 solver 失败: %w", err)
	}

	/* 异步捕获 stderr 最后 2KB 用于错误诊断 */
	var stderrBuf bytes.Buffer
	if pipeErr == nil {
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stderrPipe.Read(buf)
				if n > 0 {
					stderrBuf.Write(buf[:n])
					/* 只保留最后 2KB */
					if stderrBuf.Len() > 2048 {
						b := stderrBuf.Bytes()
						stderrBuf.Reset()
						stderrBuf.Write(b[len(b)-2048:])
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}

	/* 监控子进程退出 */
	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	/*
	  cleanup 停止 solver 及其所有子进程（浏览器等）。
	  Windows: taskkill /T /F 杀进程树
	  Unix: kill 主进程
	*/
	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			if cmd.Process == nil {
				return
			}
			slog.Info("正在停止 Solver 进程树...")
			killProcessTree(cmd)
			/* exitCh 中的 Wait 会在进程结束后返回，这里不再重复 Wait */
			slog.Info("Solver 已停止")
		})
	}

	/* 等待 solver 就绪，同时检测子进程是否已崩溃 */
	checkURL := fmt.Sprintf("http://127.0.0.1:%s/result?id=health", port)
	ready := false
	for i := 0; i < 120; i++ {
		select {
		case exitErr := <-exitCh:
			/* 子进程已退出，说明崩溃了 */
			errMsg := stderrBuf.String()
			if errMsg == "" {
				errMsg = "无 stderr 输出"
			}
			return nil, fmt.Errorf("solver 进程已退出(%v):\n%s", exitErr, errMsg)
		case <-time.After(1 * time.Second):
		}
		resp, err := http.Get(checkURL)
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
	}
	if !ready {
		cleanup()
		errMsg := stderrBuf.String()
		if errMsg != "" {
			return nil, fmt.Errorf("solver 启动超时（120s）:\n%s", errMsg)
		}
		return nil, fmt.Errorf("solver 启动超时（120s），请检查 Python 环境")
	}
	slog.Info("Solver 就绪")
	return cleanup, nil
}

/*
ensureSolver 确保 solver 可用。
先尝试连接，连不上就自动启动本地 solver。
返回 cleanup 函数（如果启动了子进程）和实际使用的 browsers 数。
*/
func ensureSolver(solverURL string, browsers int) (cleanup func(), actualBrowsers int, err error) {
	/* 先检测是否已有 solver 在运行 */
	if isSolverReachable(solverURL) {
		slog.Info("Solver 已在运行", "url", solverURL)
		return nil, browsers, nil
	}

	/* 连不上，尝试自动启动 */
	slog.Warn("无法连接 Solver，尝试自动启动本地 Solver...", "url", solverURL)

	solverDir := findSolverDir()
	if solverDir == "" {
		return nil, 0, fmt.Errorf("无法连接 Solver(%s) 且未找到 solver/ 目录，无法自动启动", solverURL)
	}

	/* 如果未指定 browsers 数量，默认 4 */
	if browsers <= 0 {
		browsers = 4
	}

	/* 从 URL 提取端口 */
	port := "5072"
	if u, err := url.Parse(solverURL); err == nil && u.Port() != "" {
		port = u.Port()
	}

	cleanup, err = startSolver(browsers, port)
	if err != nil {
		return nil, 0, err
	}
	return cleanup, browsers, nil
}

func main() {
	count := flag.Int("count", 1, "注册账号数量")
	concurrent := flag.Int("concurrent", 1, "并发数")
	workers := flag.Int("workers", 0, "验证码预解并发数 (默认=concurrent*2 或 browsers)")
	browsers := flag.Int("browsers", 0, "Solver 浏览器线程数 (自动启动时使用，默认4)")
	solverURL := flag.String("solver", "http://127.0.0.1:5072", "Turnstile Solver 地址 (多个用逗号分隔)")
	dataDir := flag.String("data", ".", "数据文件保存目录")
	flag.Parse()
	slog.SetDefault(slog.New(&ColorHandler{level: slog.LevelDebug}))

	/* 注册信号处理，确保子进程能被清理 */
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	/*
	  确保 Solver 可用：
	  1. 先尝试连接已有 solver
	  2. 连不上 → 自动查找 solver/ 目录 → 安装依赖 → 启动
	*/
	firstURL := strings.Split(*solverURL, ",")[0]
	solverCleanup, actualBrowsers, err := ensureSolver(strings.TrimSpace(firstURL), *browsers)
	if err != nil {
		slog.Error("Solver 不可用", "err", err)
		os.Exit(1)
	}
	if solverCleanup != nil {
		defer solverCleanup()
	}

	/* 确定 workers 数量 */
	if *workers <= 0 {
		if actualBrowsers > 0 {
			*workers = actualBrowsers
		} else {
			*workers = *concurrent * 2
		}
	}

	/* 后台监听信号，收到后执行清理 */
	go func() {
		<-sigCh
		slog.Info("收到中断信号，正在退出...")
		if solverCleanup != nil {
			solverCleanup()
		}
		os.Exit(0)
	}()

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
