package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/fatih/color"
	"github.com/valyala/fasthttp"
)

type Config struct {
	DelayMS     int      `json:"delay_ms"`
	GuildIDs    []string `json:"guild_ids"`
	WebhookURL  string   `json:"webhook_url"`
	TokensFile  string   `json:"tokens_file"`
	VanityFile  string   `json:"vanities_file"`
	ProxiesFile string   `json:"proxies_file"`
}

var (
	proxyIndex int = 0
	proxies    []string
	mu         sync.Mutex
)

type MFAResponse struct {
	Token string `json:"token"`
}

type VanityResponse struct {
	MFA struct {
		Ticket string `json:"ticket"`
	} `json:"mfa"`
}

var (
	hosts        = []string{"discord.com", "canary.discord.com", "ptb.discord.com"}
	versions     = []string{"v7", "v8", "v9", "v10"}
	successCount int64
	failCount    int64
	totalCount   int64

	mfaTokens = make(map[string]string)
	blacklist = make(map[string]time.Time)

	cfg Config
)

var fastHttpClient = &fasthttp.Client{
	Dial: func(addr string) (net.Conn, error) {
		mu.Lock()
		if len(proxies) == 0 {
			mu.Unlock()
			return net.DialTimeout("tcp", addr, 5*time.Second)
		}
		proxy := proxies[proxyIndex]
		mu.Unlock()

		auth := ""
		host := proxy

		if strings.Contains(proxy, "@") {
			split := strings.Split(proxy, "@")
			auth = base64.StdEncoding.EncodeToString([]byte(split[0]))
			host = split[1]
		}

		conn, err := net.DialTimeout("tcp", host, 5*time.Second)
		if err != nil {
			return nil, err
		}
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if auth != "" {
			req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
		}
		req += "\r\n"

		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, err
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if !strings.Contains(string(buf[:n]), "200") {
			conn.Close()
			return nil, fmt.Errorf("proxy connect failed: %s", string(buf[:n]))
		}

		return conn, nil
	},

	TLSConfig: &tls.Config{
		InsecureSkipVerify:       true,
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256},
		SessionTicketsDisabled: true,
	},
	ReadTimeout:                   30 * time.Second,
	WriteTimeout:                  30 * time.Second,
	MaxConnsPerHost:               50,
	MaxIdleConnDuration:           30 * time.Second,
	DisableHeaderNamesNormalizing: true,
	NoDefaultUserAgentHeader:      true,
}

var fastClient = fastHttpClient

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var setConsoleTitleProc = kernel32.NewProc("SetConsoleTitleW")

func setTitle(t string) {
	p, _ := syscall.UTF16PtrFromString(t)
	setConsoleTitleProc.Call(uintptr(unsafe.Pointer(p)))
}

func printBanner() {
	setTitle(fmt.Sprintf("@duck.js | Total: %d | Success: %d | Fail: %d",
		totalCount, successCount, failCount))
}

func loadProxies(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		color.New(color.FgHiRed).Printf("[ERROR] Proxies file could not be read: %v\n", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			proxies = append(proxies, line)
		}
	}

	color.New(color.FgHiGreen).Printf("[INFO] Loaded %d proxies\n", len(proxies))
}

func loadTokens(path string) [][2]string {
	f, err := os.Open(path)
	if err != nil {
		color.New(color.FgHiRed).Fprintf(os.Stderr, "[FATAL] Token file error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var pairs [][2]string
	for scanner.Scan() {
		split := strings.SplitN(scanner.Text(), ":", 2)
		if len(split) == 2 {
			pairs = append(pairs, [2]string{split[0], split[1]})
		}
	}
	return pairs
}

func loadVanities(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		color.New(color.FgHiRed).Fprintf(os.Stderr, "[FATAL] Vanity file error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var vanities []string
	for scanner.Scan() {
		v := strings.TrimSpace(scanner.Text())
		if v != "" {
			vanities = append(vanities, v)
		}
	}
	return vanities
}

func buildURL(guildID string) string {
	host := hosts[rand.Intn(len(hosts))]
	version := versions[rand.Intn(len(versions))]
	return fmt.Sprintf("https://%s/api/%s/guilds/%s/vanity-url", host, version, guildID)
}

func setHeaders(req *fasthttp.Request, token string) {
	req.Header.Set("Authorization", token)
	if mfa, ok := mfaTokens[token]; ok {
		req.Header.Set("X-Discord-Mfa-Authorization", mfa)
		req.Header.Set("Cookie", "__Secure-recent_mfa="+mfa)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x32) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9164 Chrome/124.0.6367.243 Electron/30.2.0 duckeevilllssss/537.36")
	req.Header.Set("X-Super-Properties", "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MTY0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMjI2MzEiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoidHIiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBkaXNjb3JkLzEuMC45MTY0IENocm9tZS8xMjQuMC42MzY3LjI0MyBFbGVjdHJvbi8zMC4yLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjMwLjIuMCIsIm9zX3Nka192ZXJzaW9uIjoiMjI2MzEiLCJjbGllbnRfdnVibF9udW1iZXIiOjUyODI2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==")
	req.Header.Set("X-Discord-Timezone", "Europe/Istanbul")
	req.Header.Set("X-Discord-Locale", "en-US")
	req.Header.Set("X-Debug-Options", "bugReporterEnabled")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Priority", "u=1, i")
	req.Header.Set("Sec-CH-UA", `"Not)A;Brand";v="8", "Chromium";v="138"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-Debug-Options", "bugReporterEnabled")
	req.Header.Set("X-Discord-Locale", "en-US")
	req.Header.Set("X-Audit-Log-Reason", "duckevils spammer")
	req.Header.Set("Connection", "keep-alive")
}

const maxMfaRetries = 1

func tryClaimVanity(token, pass, guildID, vanity string, mfaRetryCount int) bool {
	timestamp := time.Now().Format("15:04:05")
	shortToken := token[:10] + "..."

	atomic.AddInt64(&totalCount, 1)
	printBanner()

	color.New(color.FgHiYellow).Printf("[%s][INFO] Trying to claim ", timestamp)
	color.New(color.FgHiCyan).Printf("%s", vanity)
	color.New(color.FgHiYellow).Printf(" for guild ")
	color.New(color.FgHiBlue).Printf("%s", guildID)
	color.New(color.FgHiYellow).Printf(" with token ")
	color.New(color.FgHiMagenta).Printf("%s\n", shortToken)

	url := buildURL(guildID)
	payload := []byte(`{"code":"` + vanity + `"}`)

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("PATCH")
	setHeaders(req, token)
	req.SetBody(payload)

	if err := fastClient.Do(req, resp); err != nil {
		color.New(color.FgHiRed).Printf("[ERROR] Request failed: %v\n", err)
		return false
	}

	code := resp.StatusCode()
	body := resp.Body()

	color.New(color.FgHiYellow).Printf("[%s][INFO] Response code: ", timestamp)
	color.New(color.FgHiMagenta).Printf("%d\n", code)

	switch code {
	case fasthttp.StatusOK:
		color.New(color.FgHiGreen).Printf("[%s][SUCCESS] %s claimed for guild %s\n",
			timestamp, vanity, guildID)
		atomic.AddInt64(&successCount, 1)
		postWebhook("vanity Claimed", vanity, guildID, body)
		return true
	case fasthttp.StatusUnauthorized:
		if mfaRetryCount >= maxMfaRetries {
			color.New(color.FgHiRed).Printf("[%s][ERROR] Max MFA retries reached\n", timestamp)
			return false
		}
		var vr VanityResponse
		if err := json.Unmarshal(body, &vr); err != nil {
			color.New(color.FgHiRed).Println("[ERROR] Failed to parse MFA response")
			return false
		}
		ticket := vr.MFA.Ticket
		if ticket == "" {
			color.New(color.FgHiRed).Println("[ERROR] MFA ticket not found")
			return false
		}
		color.New(color.FgHiCyan).Printf("[INFO] MFA ticket received: %s\n", ticket)
		newToken := sendMFA(token, ticket, pass)
		if newToken == "" || newToken == "err" {
			color.New(color.FgHiRed).Println("[ERROR] MFA failed")
			return false
		}
		mfaTokens[token] = newToken
		return tryClaimVanity(token, pass, guildID, vanity, mfaRetryCount+1)

	case fasthttp.StatusForbidden:
		color.New(color.FgMagenta).Printf("[RATE] RATE LIMITED. Blacklisting token %s\n", shortToken)
		blacklist[token] = time.Now().Add(10 * time.Minute)
		atomic.AddInt64(&failCount, 1)
		return false
	default:
		color.New(color.FgHiRed).Printf("[FAIL] Guild %s response: %s\n", guildID, string(body))
		atomic.AddInt64(&failCount, 1)
		return false
	}
}
func testFastHttpClient() {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://api.ipify.org?format=text")
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", "duckevils")

	err := fastHttpClient.Do(req, resp)
	if err != nil {
		color.New(color.FgRed).Printf("[TEST FAIL] Proxy connection failed: %v\n", err)
		return
	}

	ip := string(resp.Body())
	color.New(color.FgGreen).Printf("[TEST OK] Proxy IP: %s (Status: %d)\n", ip, resp.StatusCode())
}

func sendMFA(token, ticket, pass string) string {
	type MFAPayload struct {
		Ticket string `json:"ticket"`
		Type   string `json:"mfa_type"`
		Data   string `json:"data"`
	}

	color.New(color.FgHiBlue).Printf("[MFA] VERIFYING MFA\n")

	payload := MFAPayload{
		Ticket: ticket,
		Type:   "password",
		Data:   pass,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		color.New(color.FgHiRed).Printf("Error marshalling payload: %v\n", err)
		return "err"
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://canary.discord.com/api/v7/mfa/finish")
	req.Header.SetMethod("POST")
	setHeaders(req, token)
	req.SetBody(jsonPayload)

	if err := fastHttpClient.Do(req, resp); err != nil {
		return "err"
	}

	if resp.StatusCode() == fasthttp.StatusOK {
		var mfaResponse MFAResponse
		if err := json.Unmarshal(resp.Body(), &mfaResponse); err != nil {
			return "err"
		}
		return mfaResponse.Token

	}
	return "err"
}
func postWebhook(title, vanity, guildID string, respBody []byte) {
	data := map[string]interface{}{
		"content":    fmt.Sprintf("*%s* @everyone", vanity),
		"username":   "duckevils",
		"avatar_url": "https://cdn.discordapp.com/attachments/1344021012282474626/1388131140711354571/1743515420105_et751l_2_0_1.jpg?ex=685fdd5e&is=685e8bde&hm=080d4e504d87b05a3c6f92d8fd7333b8f14d3eeff5cc540bacb95bb0a481e33e&",
		"embeds": []map[string]interface{}{
			{
				"title":       "vanity url spammer",
				"description": fmt.Sprintf("```json\n%s\n```", string(respBody)),
				"color":       0x000000,
				"fields": []map[string]interface{}{
					{"name": "Vanity URL", "value": fmt.Sprintf("`%s`", vanity), "inline": true},
					{"name": "Guild ID", "value": fmt.Sprintf("`%s`", guildID), "inline": true},
					{"name": "Req count", "value": fmt.Sprintf("`%d`", atomic.LoadInt64(&totalCount)), "inline": true},
				},
				"footer": map[string]interface{}{
					"text":     fmt.Sprintf("t.me/vanitydeal | %s", time.Now().Format("02.01.2006 15:04:05")),
					"icon_url": "https://tenor.com/view/happy-monkey-dance-funny-gif-18218386",
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	b, err := json.Marshal(data)
	if err != nil {
		return
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(cfg.WebhookURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(b)

	if err := fastClient.Do(req, resp); err != nil {
		return
	}
}
func rotateProxy() {
	mu.Lock()
	defer mu.Unlock()
	if len(proxies) == 0 {
		return
	}
	proxyIndex = (proxyIndex + 1) % len(proxies)
	color.New(color.FgHiBlue).Printf("[PROXY] Rotated to proxy: %s\n", proxies[proxyIndex])
}

func main() {
	timestamp := time.Now().Format("15:04:05")

	color.New(color.FgHiCyan).Println("[BOOTING] VANITY SPAMMER LAUNCHING..." + timestamp)
	color.New(color.FgHiRed).Println("developed by @duck.js\n")

	time.Sleep(3 * time.Second)

	data, err := os.ReadFile("config.json")
	if err != nil {
		color.New(color.FgHiRed).Fprintf(os.Stderr, "[ERROR] config.json okunamadı: %v\n", err)
		return
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		color.New(color.FgHiRed).Fprintf(os.Stderr, "[ERROR] config parse hatası: %v\n", err)
		return
	}

	loadProxies(cfg.ProxiesFile)
	testFastHttpClient()
	pairs := loadTokens(cfg.TokensFile)
	vanities := loadVanities(cfg.VanityFile)
	delay := time.Duration(cfg.DelayMS) * time.Millisecond

	if len(pairs) == 0 || len(cfg.GuildIDs) == 0 || len(vanities) == 0 {
		color.New(color.FgHiRed).Println("[ERROR] tokens, guilds or vanities missing!")
		return
	}

	color.New(color.FgHiGreen).Printf("[READY] Loaded %d tokens, %d guilds, %d vanities\n",
		len(pairs), len(cfg.GuildIDs), len(vanities))

	for {
		tokenPair := pairs[rand.Intn(len(pairs))]
		token, pass := tokenPair[0], tokenPair[1]

		if until, exists := blacklist[token]; exists && time.Now().Before(until) {
			color.New(color.FgYellow).Printf("[SKIP] Token blacklisted: %s\n", token)
			time.Sleep(delay)
			continue
		}

		gid := cfg.GuildIDs[rand.Intn(len(cfg.GuildIDs))]
		vanity := vanities[rand.Intn(len(vanities))]

		func() {
			defer func() {
				if r := recover(); r != nil {
					color.New(color.FgYellow).Printf("[WARN] panic yakalandı: %v\n", r)
				}
			}()

			randDelay := time.Duration(rand.Intn(3000)+2000) * time.Millisecond
			time.Sleep(randDelay)
			ok := tryClaimVanity(token, pass, gid, vanity, 0)
			if ok {
				color.New(color.FgHiGreen).Printf("[SUCCESS] Claimed: %s for %s\n", vanity, gid)
				select {}
			}
		}()
		rotateProxy()
		testFastHttpClient()
		time.Sleep(delay)
	}
}
