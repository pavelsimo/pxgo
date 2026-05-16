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
)

const (
	LogNone = iota
	LogScriptDir
	LogCWD
	LogUniqLog
	LogStdout
)

const LogStdoutTarget = "<stdout>"

var Defaults = map[string]string{
	"server":          "",
	"pac":             "",
	"pac_encoding":    "utf-8",
	"port":            "3128",
	"listen":          "127.0.0.1",
	"gateway":         "0",
	"hostonly":        "0",
	"allow":           "*.*.*.*",
	"noproxy":         "",
	"useragent":       "",
	"username":        "",
	"auth":            "",
	"kerberos":        "0",
	"workers":         "1",
	"threads":         "32",
	"idle":            "30",
	"socktimeout":     "20.0",
	"proxyreload":     "60",
	"foreground":      "0",
	"log":             "0",
	"client_auth":     "NONE",
	"client_nosspi":   "0",
	"client_username": "",
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
	port, _ := strconv.Atoi(Defaults["port"])
	workers, _ := strconv.Atoi(Defaults["workers"])
	threads, _ := strconv.Atoi(Defaults["threads"])
	idle, _ := strconv.Atoi(Defaults["idle"])
	sockTimeout, _ := strconv.ParseFloat(Defaults["socktimeout"], 64)
	proxyReload, _ := strconv.Atoi(Defaults["proxyreload"])
	return Config{
		PACEncoding: Defaults["pac_encoding"],
		Port:        port,
		Listen:      Defaults["listen"],
		Allow:       Defaults["allow"],
		Workers:     workers,
		Threads:     threads,
		Idle:        idle,
		SockTimeout: sockTimeout,
		ProxyReload: proxyReload,
		Auth:        Defaults["auth"],
		ClientAuth:  Defaults["client_auth"],
	}
}

func GetConfigDir() string {
	if runtime.GOOS == "windows" {
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
	u, err := url.Parse(fileURL)
	if err != nil {
		return fileURL
	}
	path, _ := url.PathUnescape(u.Path)
	if u.Host != "" {
		return u.Host + path
	}
	if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		return path[1:]
	}
	return path
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
	if !seen["127.0.0.1"] {
		ips = append(ips, net.ParseIP("127.0.0.1"))
	}
	return ips
}

func ParseArgs(args []string) (Config, error) {
	cfg := Default()
	dotenv := loadDotenv()
	isSave := hasBareArg(args, "save") || truthy(os.Getenv("PX_SAVE")) || truthy(dotenv["save"])
	configPath := preScanConfigPath(args)
	if configPath == "" {
		configPath = os.Getenv("PX_CONFIG")
	}
	if configPath == "" {
		configPath = dotenv["config"]
	}
	if configPath != "" {
		cfg.ConfigPath = normalizePath(configPath)
	}
	if loadPath := ConfigPath(configPath); loadPath != "" {
		if configPath != "" && !isSave {
			if _, err := os.Stat(loadPath); err != nil {
				return cfg, fmt.Errorf("could not find config file: %s", loadPath)
			}
		}
		if fileCfg, err := ReadINI(loadPath); err == nil {
			cfg = fileCfg
			cfg.ConfigPath = loadPath
		}
	}
	cfg.Password = os.Getenv("PX_PASSWORD")
	cfg.ClientPassword = os.Getenv("PX_CLIENT_PASSWORD")
	cfg.ClientUsername = os.Getenv("PX_CLIENT_USERNAME")
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
		if name, val, ok := strings.Cut(strings.TrimPrefix(arg, "--"), "="); ok && name == "config" {
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
		if !ok || val == "" || !strings.HasPrefix(key, "PX_") || len(key) <= 3 {
			continue
		}
		_ = applyValue(cfg, strings.ToLower(key[3:]), val)
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
	f, err := os.Open(path)
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
		if !strings.HasPrefix(key, "PX_") || os.Getenv(key) != "" {
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		values[strings.ToLower(key[3:])] = val
	}
	return true
}

func applyValue(cfg *Config, name, val string) error {
	switch name {
	case "server", "proxy":
		cfg.Server = val
	case "pac":
		cfg.PAC = normalizePACLocation(val)
	case "pac_encoding":
		cfg.PACEncoding = val
	case "port":
		cfg.Port = parseIntValue(val, cfg.Port)
	case "listen":
		cfg.Listen = val
	case "gateway":
		cfg.Gateway = truthy(val)
		if cfg.Gateway {
			cfg.Listen = ""
		}
	case "hostonly":
		cfg.Hostonly = truthy(val)
		if cfg.Hostonly {
			cfg.Listen = ""
		}
	case "allow":
		cfg.Allow = val
	case "noproxy":
		cfg.NoProxy = val
	case "username":
		cfg.Username = val
	case "password":
		cfg.Password = val
	case "client_password":
		cfg.ClientPassword = val
	case "auth":
		cfg.Auth = strings.ToUpper(val)
	case "kerberos":
		cfg.Kerberos = truthy(val)
	case "workers":
		cfg.Workers = parseIntValue(val, cfg.Workers)
	case "threads":
		cfg.Threads = parseIntValue(val, cfg.Threads)
	case "idle":
		cfg.Idle = parseIntValue(val, cfg.Idle)
	case "socktimeout":
		cfg.SockTimeout = parseFloatValue(val, cfg.SockTimeout)
	case "proxyreload":
		cfg.ProxyReload = parseIntValue(val, cfg.ProxyReload)
	case "foreground":
		cfg.Foreground = truthy(val)
	case "log":
		cfg.Log = parseIntValue(val, cfg.Log)
	case "test":
		cfg.Test = val
	case "config":
		cfg.ConfigPath = normalizePath(val)
	case "client_auth":
		cfg.ClientAuth = strings.ToUpper(val)
	case "client_username":
		cfg.ClientUsername = val
	case "client_nosspi":
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
	if os.Getenv("PX_KEYRING_PLAINTEXT") != "1" {
		return errors.New("no keyring backend configured; set PX_KEYRING_PLAINTEXT=1 for plaintext storage")
	}
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

func GetPassword(realm, username string) (string, bool) {
	if username == "" || os.Getenv("PX_KEYRING_PLAINTEXT") != "1" {
		return "", false
	}
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
	if path := os.Getenv("PX_KEYRING_FILE"); path != "" {
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
		if _, err := os.Stat(path); err == nil {
			return path
		}
		return ""
	}
	if filepath.IsAbs(pac) {
		if _, err := os.Stat(pac); err == nil {
			return pac
		}
		return ""
	}
	path := filepath.Join(GetScriptDir(), pac)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func mergeMissing(dst *Config, src Config) {
	if dst.Server == "" {
		dst.Server = src.Server
	}
	if dst.PAC == "" {
		dst.PAC = src.PAC
	}
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
	return os.WriteFile(path, []byte(content), 0o644)
}

func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ReadINI(path string) (Config, error) {
	cfg := Default()
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
