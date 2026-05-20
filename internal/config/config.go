package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	LogNone = iota
	LogScriptDir
	LogCWD
	LogUniqLog
	LogStdout
)

const LogStdoutTarget = "<stdout>"

const goosWindows = "windows"

const (
	envPrefix = "PXGO_"

	keyServer         = "server"
	keyPAC            = "pac"
	keyPACEncoding    = "pac_encoding"
	keyPort           = "port"
	keyListen         = "listen"
	keyGateway        = "gateway"
	keyHostonly       = "hostonly"
	keyAllow          = "allow"
	keyNoProxy        = "noproxy"
	keyUserAgent      = "useragent"
	keyUsername       = "username"
	keyPassword       = "password"
	keyAuth           = "auth"
	keyKerberos       = "kerberos"
	keyWorkers        = "workers"
	keyThreads        = "threads"
	keyIdle           = "idle"
	keySockTimeout    = "socktimeout"
	keyProxyReload    = "proxyreload"
	keyForeground     = "foreground"
	keyLog            = "log"
	keyClientAuth     = "client_auth"
	keyClientNoSSPI   = "client_nosspi"
	keyClientUsername = "client_username"
	keyClientPassword = "client_password"
	keyConfig         = "config"
	keyTest           = "test"
	localhostIP       = "127.0.0.1"
)

var Defaults = map[string]string{
	keyServer:         "",
	keyPAC:            "",
	keyPACEncoding:    "utf-8",
	keyPort:           "3128",
	keyListen:         localhostIP,
	keyGateway:        "0",
	keyHostonly:       "0",
	keyAllow:          "*.*.*.*",
	keyNoProxy:        "",
	keyUserAgent:      "",
	keyUsername:       "",
	keyAuth:           "",
	keyKerberos:       "0",
	keyWorkers:        "1",
	keyThreads:        "32",
	keyIdle:           "30",
	keySockTimeout:    "20.0",
	keyProxyReload:    "60",
	keyForeground:     "0",
	keyLog:            "0",
	keyClientAuth:     "NONE",
	keyClientNoSSPI:   "0",
	keyClientUsername: "",
}

var executablePath = os.Executable

const (
	Realm       = "pxgo"
	ClientRealm = "pxgo-client"
)

type Config struct {
	Server               string
	PAC                  string
	PACEncoding          string
	Port                 int
	Listen               string
	Gateway              bool
	Hostonly             bool
	Allow                string
	NoProxy              string
	UserAgent            string
	Username             string
	Password             string
	Auth                 string
	Kerberos             bool
	Workers              int
	Threads              int
	Idle                 int
	SockTimeout          float64
	ProxyReload          int
	Foreground           bool
	Log                  int
	Test                 string
	TestAuth             bool
	PasswordAction       bool
	ClientPasswordAction bool
	Help                 bool
	Version              bool
	Install              bool
	Uninstall            bool
	Force                bool
	ConfigPath           string
	Save                 bool
	Quit                 bool
	Restart              bool
	ClientAuth           string
	ClientUsername       string
	ClientPassword       string
	ClientNoSSPI         bool
}

func Default() Config {
	port, _ := strconv.Atoi(Defaults[keyPort])
	workers, _ := strconv.Atoi(Defaults[keyWorkers])
	threads, _ := strconv.Atoi(Defaults[keyThreads])
	idle, _ := strconv.Atoi(Defaults[keyIdle])
	sockTimeout, _ := strconv.ParseFloat(Defaults[keySockTimeout], 64)
	proxyReload, _ := strconv.Atoi(Defaults[keyProxyReload])
	return Config{
		PACEncoding: Defaults[keyPACEncoding],
		Port:        port,
		Listen:      Defaults[keyListen],
		Allow:       Defaults[keyAllow],
		Workers:     workers,
		Threads:     threads,
		Idle:        idle,
		SockTimeout: sockTimeout,
		ProxyReload: proxyReload,
		Auth:        Defaults[keyAuth],
		ClientAuth:  Defaults[keyClientAuth],
	}
}

func GetConfigDir() string {
	if runtime.GOOS == goosWindows {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "pxgo")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "pxgo")
	}
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "pxgo")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "pxgo")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "pxgo")
}

func GetLogfile(location int) string {
	switch location {
	case LogScriptDir:
		return filepath.Join(GetScriptDir(), "debug-main.log")
	case LogCWD:
		cwd, err := os.Getwd()
		if err != nil {
			return "debug-main.log"
		}
		return filepath.Join(cwd, "debug-main.log")
	case LogUniqLog:
		cwd, err := os.Getwd()
		if err != nil {
			cwd = "."
		}
		name := "main"
		for _, arg := range os.Args {
			if port, ok := strings.CutPrefix(arg, "--port="); ok {
				name = port + "-" + name
				break
			}
		}
		return filepath.Join(cwd, fmt.Sprintf("debug-%s-%d.log", name, time.Now().UnixNano()))
	case LogStdout:
		return LogStdoutTarget
	default:
		return ""
	}
}

func FileURLToLocalPath(fileURL string) string {
	normalized := strings.ReplaceAll(fileURL, "\\", "/")
	u, err := url.Parse(normalized)
	if err != nil {
		return fileURL
	}
	path, _ := url.PathUnescape(u.Path)
	var result string
	switch {
	case u.Host != "":
		result = u.Host + path
	case len(path) >= 3 && path[0] == '/' && path[2] == ':':
		result = path[1:]
	default:
		result = path
	}
	return filepath.FromSlash(result)
}

func GetHostIPs() []net.IP {
	seen := map[string]bool{}
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip4 := ip.To4(); ip4 != nil && !seen[ip4.String()] {
					seen[ip4.String()] = true
					ips = append(ips, ip4)
				}
			}
		}
	}
	if !seen[localhostIP] {
		ips = append(ips, net.ParseIP(localhostIP))
	}
	return ips
}

func ParseArgs(args []string) (Config, error) {
	cfg := Default()
	dotenv := loadDotenv()
	isSave := hasBareArg(args, "save") || truthy(os.Getenv(envPrefix+"SAVE")) || truthy(dotenv["save"])
	configPath := preScanConfigPath(args)
	if configPath == "" {
		configPath = os.Getenv(envPrefix + "CONFIG")
	}
	if configPath == "" {
		configPath = dotenv[keyConfig]
	}
	if configPath != "" {
		cfg.ConfigPath = normalizePath(configPath)
	}
	if loadPath := ConfigPath(configPath); loadPath != "" {
		if configPath != "" && !isSave {
			if _, err := os.Stat(loadPath); err != nil { // #nosec G703 -- config paths are explicitly user-controlled inputs.
				return cfg, fmt.Errorf("could not find config file: %s", loadPath)
			}
		}
		if fileCfg, err := ReadINI(loadPath); err == nil {
			cfg = fileCfg
			cfg.ConfigPath = loadPath
		}
	}
	cfg.Password = os.Getenv(envPrefix + "PASSWORD")
	cfg.ClientPassword = os.Getenv(envPrefix + "CLIENT_PASSWORD")
	cfg.ClientUsername = os.Getenv(envPrefix + "CLIENT_USERNAME")
	applyMap(&cfg, dotenv)
	applyEnv(&cfg)
	for _, arg := range args {
		if arg == "--save" {
			cfg.Save = true
			continue
		}
		if arg == "--quit" {
			cfg.Quit = true
			continue
		}
		if arg == "--restart" {
			cfg.Restart = true
			continue
		}
		if arg == "--gateway" {
			cfg.Gateway = true
			cfg.Listen = ""
			continue
		}
		if arg == "--hostonly" {
			cfg.Hostonly = true
			cfg.Listen = ""
			continue
		}
		if arg == "--verbose" {
			cfg.Log = LogStdout
			cfg.Foreground = true
			continue
		}
		if arg == "--debug" {
			cfg.Log = LogScriptDir
			continue
		}
		if arg == "--uniqlog" {
			cfg.Log = LogUniqLog
			continue
		}
		if arg == "--foreground" {
			cfg.Foreground = true
			continue
		}
		if arg == "--test-auth" {
			cfg.TestAuth = true
			continue
		}
		if arg == "--test" {
			cfg.Test = "1"
			continue
		}
		if arg == "--client-nosspi" || arg == "--client_nosspi" {
			cfg.ClientNoSSPI = true
			continue
		}
		if arg == "-h" || arg == "--help" {
			cfg.Help = true
			continue
		}
		if arg == "--version" {
			cfg.Version = true
			continue
		}
		if arg == "--install" {
			cfg.Install = true
			continue
		}
		if arg == "--uninstall" {
			cfg.Uninstall = true
			continue
		}
		if arg == "--force" {
			cfg.Force = true
			continue
		}
		if arg == "--password" {
			cfg.PasswordAction = true
			continue
		}
		if arg == "--client-password" {
			cfg.ClientPasswordAction = true
			continue
		}
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		name, val, ok := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !ok {
			name, val = strings.TrimPrefix(arg, "--"), "1"
		}
		if err := applyValue(&cfg, strings.ReplaceAll(name, "-", "_"), val); err != nil {
			return cfg, err
		}
	}
	loadStoredPasswords(&cfg)
	normalizeDependencies(&cfg)
	return cfg, nil
}

func preScanConfigPath(args []string) string {
	for _, arg := range args {
		if name, val, ok := strings.Cut(strings.TrimPrefix(arg, "--"), "="); ok && name == keyConfig {
			return val
		}
	}
	return ""
}

func hasBareArg(args []string, name string) bool {
	want := "--" + name
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func applyEnv(cfg *Config) {
	for _, item := range os.Environ() {
		key, val, ok := strings.Cut(item, "=")
		if !ok || val == "" || !strings.HasPrefix(key, envPrefix) || len(key) <= len(envPrefix) {
			continue
		}
		_ = applyValue(cfg, strings.ToLower(key[len(envPrefix):]), val)
	}
}

func applyMap(cfg *Config, values map[string]string) {
	for key, val := range values {
		if val != "" {
			_ = applyValue(cfg, key, val)
		}
	}
}

func loadDotenv() map[string]string {
	values := map[string]string{}
	if !loadDotenvFile(filepath.Join(".", ".env"), values) {
		cwd, _ := os.Getwd()
		scriptEnv := filepath.Join(GetScriptDir(), ".env")
		if filepath.Dir(scriptEnv) != cwd {
			loadDotenvFile(scriptEnv, values)
		}
	}
	return values
}

func loadDotenvFile(path string, values map[string]string) bool {
	f, err := os.Open(path) // #nosec G703 -- config paths are explicitly user-controlled inputs.
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !strings.HasPrefix(key, envPrefix) || os.Getenv(key) != "" {
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		values[strings.ToLower(key[len(envPrefix):])] = val
	}
	return true
}

func applyValue(cfg *Config, name, val string) error {
	switch name {
	case keyServer, "proxy":
		cfg.Server = val
	case keyPAC:
		cfg.PAC = normalizePACLocation(val)
	case keyPACEncoding:
		cfg.PACEncoding = val
	case keyPort:
		cfg.Port = parseIntValue(val, cfg.Port)
	case keyListen:
		cfg.Listen = val
	case keyGateway:
		cfg.Gateway = truthy(val)
		if cfg.Gateway {
			cfg.Listen = ""
		}
	case keyHostonly:
		cfg.Hostonly = truthy(val)
		if cfg.Hostonly {
			cfg.Listen = ""
		}
	case keyAllow:
		cfg.Allow = val
	case keyNoProxy:
		cfg.NoProxy = val
	case keyUsername:
		cfg.Username = val
	case keyPassword:
		cfg.Password = val
	case keyClientPassword:
		cfg.ClientPassword = val
	case keyAuth:
		cfg.Auth = strings.ToUpper(val)
	case keyKerberos:
		cfg.Kerberos = truthy(val)
	case keyWorkers:
		cfg.Workers = parseIntValue(val, cfg.Workers)
	case keyThreads:
		cfg.Threads = parseIntValue(val, cfg.Threads)
	case keyIdle:
		cfg.Idle = parseIntValue(val, cfg.Idle)
	case keySockTimeout:
		cfg.SockTimeout = parseFloatValue(val, cfg.SockTimeout)
	case keyProxyReload:
		cfg.ProxyReload = parseIntValue(val, cfg.ProxyReload)
	case keyForeground:
		cfg.Foreground = truthy(val)
	case keyLog:
		cfg.Log = parseIntValue(val, cfg.Log)
	case keyTest:
		cfg.Test = val
	case keyConfig:
		cfg.ConfigPath = normalizePath(val)
	case keyClientAuth:
		cfg.ClientAuth = strings.ToUpper(val)
	case keyClientUsername:
		cfg.ClientUsername = val
	case keyClientNoSSPI:
		cfg.ClientNoSSPI = truthy(val)
	default:
		return fmt.Errorf("unsupported option %s", name)
	}
	return nil
}

func parseIntValue(val string, current int) int {
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return current
	}
	return parsed
}

func parseFloatValue(val string, current float64) float64 {
	parsed, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return current
	}
	return parsed
}

func normalizeDependencies(cfg *Config) {
	if cfg.Gateway || cfg.Hostonly {
		cfg.Listen = ""
	}
	if cfg.Hostonly && !cfg.Gateway {
		cfg.Allow = ""
	}
}

func loadStoredPasswords(cfg *Config) {
	if cfg.Password == "" && cfg.Username != "" {
		if pwd, ok := GetPassword(Realm, cfg.Username); ok {
			cfg.Password = pwd
		}
	}
	if cfg.ClientPassword == "" && cfg.ClientUsername != "" {
		if pwd, ok := GetPassword(ClientRealm, cfg.ClientUsername); ok {
			cfg.ClientPassword = pwd
		}
	}
}

func StorePassword(realm, username, password string) error {
	if username == "" {
		return errors.New("username is required")
	}
	if password == "" {
		return errors.New("password is required")
	}
	// PXGO_KEYRING_PLAINTEXT=1 bypasses the OS keyring (useful for Docker/CI).
	if os.Getenv(envPrefix+"KEYRING_PLAINTEXT") == "1" {
		return storePlaintext(realm, username, password)
	}
	if err := keyring.Set(realm, username, password); err == nil {
		return nil
	}
	return errors.New("no keyring backend available; set PXGO_KEYRING_PLAINTEXT=1 for plaintext storage")
}

func GetPassword(realm, username string) (string, bool) {
	if username == "" {
		return "", false
	}
	if os.Getenv(envPrefix+"KEYRING_PLAINTEXT") == "1" {
		return getPlaintext(realm, username)
	}
	if pwd, err := keyring.Get(realm, username); err == nil {
		return pwd, true
	}
	return "", false
}

func storePlaintext(realm, username, password string) error {
	path := keyringPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data := map[string]map[string]string{}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &data)
	}
	if data[realm] == nil {
		data[realm] = map[string]string{}
	}
	data[realm][username] = password
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func getPlaintext(realm, username string) (string, bool) {
	raw, err := os.ReadFile(keyringPath())
	if err != nil {
		return "", false
	}
	data := map[string]map[string]string{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", false
	}
	password := data[realm][username]
	return password, password != ""
}

func keyringPath() string {
	if path := os.Getenv(envPrefix + "KEYRING_FILE"); path != "" {
		return path
	}
	return filepath.Join(GetConfigDir(), "keyring.json")
}

func truthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func normalizePACLocation(pac string) string {
	if pac == "" || strings.HasPrefix(pac, "http://") || strings.HasPrefix(pac, "https://") {
		return pac
	}
	if strings.HasPrefix(pac, "file:") {
		path := FileURLToLocalPath(pac)
		if _, err := os.Stat(path); err == nil { // #nosec G703 -- PAC paths are explicitly user-configured.
			return path
		}
		return ""
	}
	if filepath.IsAbs(pac) {
		if _, err := os.Stat(pac); err == nil { // #nosec G703 -- PAC paths are explicitly user-configured.
			return pac
		}
		return ""
	}
	path := filepath.Join(GetScriptDir(), pac)
	if _, err := os.Stat(path); err == nil { // #nosec G703 -- relative PAC paths are resolved against the executable directory.
		return path
	}
	return ""
}

func ConfigPath(explicit string) string {
	if explicit != "" {
		return normalizePath(explicit)
	}
	if _, err := os.Stat("pxgo.ini"); err == nil {
		abs, _ := filepath.Abs("pxgo.ini")
		return abs
	}
	configPath := filepath.Join(GetConfigDir(), "pxgo.ini")
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}
	scriptPath := filepath.Join(GetScriptDir(), "pxgo.ini")
	if _, err := os.Stat(scriptPath); err == nil {
		return scriptPath
	}
	return configPath
}

func ConfigPathForSave(explicit string) string {
	if explicit != "" {
		return normalizePath(explicit)
	}
	cwdPath, _ := filepath.Abs("pxgo.ini")
	if isWritableFile(cwdPath) {
		return cwdPath
	}
	configPath := filepath.Join(GetConfigDir(), "pxgo.ini")
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}
	scriptPath := filepath.Join(GetScriptDir(), "pxgo.ini")
	if isWritableFile(scriptPath) {
		return scriptPath
	}
	return configPath
}

func normalizePath(path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

func GetScriptDir() string {
	exe, err := executablePath()
	if err != nil || exe == "" {
		return "."
	}
	return filepath.Dir(exe)
}

func GetScriptCmd() string {
	if len(os.Args) > 0 && os.Args[0] != "" {
		return os.Args[0]
	}
	exe, err := executablePath()
	if err != nil || exe == "" {
		return "pxgo"
	}
	return exe
}

func IsCompiled() bool {
	return true
}

func isWritableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func SaveINI(path string, cfg Config) error {
	if path == "" {
		return errors.New("empty config path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	listen := cfg.Listen
	if cfg.Gateway || cfg.Hostonly {
		listen = ""
	}
	content := fmt.Sprintf(`[proxy]
server = %s
pac = %s
pac_encoding = %s
port = %d
listen = %s
gateway = %d
hostonly = %d
allow = %s
noproxy = %s
useragent = %s
username = %s
auth = %s
kerberos = %d

[client]
client_auth = %s
client_username = %s
client_nosspi = %d

[settings]
workers = %d
threads = %d
idle = %d
socktimeout = %g
proxyreload = %d
foreground = %d
log = %d
`, cfg.Server, cfg.PAC, cfg.PACEncoding, cfg.Port, listen, btoi(cfg.Gateway), btoi(cfg.Hostonly), cfg.Allow, cfg.NoProxy,
		cfg.UserAgent, cfg.Username, cfg.Auth, btoi(cfg.Kerberos), cfg.ClientAuth, cfg.ClientUsername, btoi(cfg.ClientNoSSPI), cfg.Workers, cfg.Threads, cfg.Idle,
		cfg.SockTimeout, cfg.ProxyReload, btoi(cfg.Foreground), cfg.Log)
	return os.WriteFile(path, []byte(content), 0o600)
}

func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ReadINI(path string) (Config, error) {
	cfg := Default()
	// #nosec G703 -- config paths are explicitly user-controlled inputs.
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		_ = applyValue(&cfg, strings.TrimSpace(k), strings.TrimSpace(v))
	}
	normalizeDependencies(&cfg)
	return cfg, scanner.Err()
}
