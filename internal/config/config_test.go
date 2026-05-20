package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	required := []string{"server", "pac", "port", "listen", "gateway", "hostonly", "allow", "noproxy", "username", "auth", "workers", "threads", "idle", "socktimeout", "proxyreload", "foreground", "log", "client_auth", "client_nosspi", "client_username"}
	for _, key := range required {
		if _, ok := Defaults[key]; !ok {
			t.Fatalf("missing default %s", key)
		}
	}
	if Defaults["port"] != "3128" || Defaults["listen"] != "127.0.0.1" || Defaults["workers"] != "1" || Defaults["threads"] != "32" || Defaults["client_auth"] != "NONE" {
		t.Fatalf("unexpected defaults: %#v", Defaults)
	}
}

func TestGetConfigDir(t *testing.T) {
	tmp := t.TempDir()
	if runtime.GOOS == goosWindows {
		t.Setenv("APPDATA", tmp)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmp)
	}
	got := GetConfigDir()
	if got != filepath.Join(tmp, "pxgo") {
		t.Fatalf("got %s", got)
	}
}

func TestGetLogfile(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	if got := GetLogfile(LogNone); got != "" {
		t.Fatalf("LogNone got %q", got)
	}
	if got := GetLogfile(LogStdout); got != LogStdoutTarget {
		t.Fatalf("LogStdout got %q", got)
	}
	if got := GetLogfile(LogCWD); got != filepath.Join(tmp, "debug-main.log") {
		t.Fatalf("LogCWD got %q", got)
	}
	if got := GetLogfile(LogUniqLog); !strings.HasPrefix(got, filepath.Join(tmp, "debug-main-")) || !strings.HasSuffix(got, ".log") {
		t.Fatalf("LogUniqLog got %q", got)
	}
}

func TestGetScriptCmd(t *testing.T) {
	if got := GetScriptCmd(); got == "" {
		t.Fatal("expected script command")
	}
}

func TestIsCompiled(t *testing.T) {
	if !IsCompiled() {
		t.Fatal("Go build should report compiled")
	}
}

func TestFileURLToLocalPath(t *testing.T) {
	if got := FileURLToLocalPath("file:///etc/proxy.pac"); !strings.Contains(got, "proxy.pac") {
		t.Fatalf("got %q", got)
	}
	if got := FileURLToLocalPath("file:///C:/Users/test/proxy.pac"); !strings.Contains(got, "C:") {
		t.Fatalf("got %q", got)
	}
}

func TestParseArgsNormalizesPACLocations(t *testing.T) {
	scriptDir := t.TempDir()
	pacPath := filepath.Join(scriptDir, "proxy.pac")
	if err := os.WriteFile(pacPath, []byte(`function FindProxyForURL(){ return "DIRECT"; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	oldExecutablePath := executablePath
	t.Cleanup(func() { executablePath = oldExecutablePath })
	executablePath = func() (string, error) {
		return filepath.Join(scriptDir, "pxgo"), nil
	}
	cfg, err := ParseArgs([]string{"--pac=proxy.pac"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PAC != pacPath {
		t.Fatalf("relative pac got %q want %q", cfg.PAC, pacPath)
	}
	cfg, err = ParseArgs([]string{"--pac=file://" + pacPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PAC != pacPath {
		t.Fatalf("file pac got %q want %q", cfg.PAC, pacPath)
	}
	cfg, err = ParseArgs([]string{"--pac=missing.pac"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PAC != "" {
		t.Fatalf("missing pac should be ignored, got %q", cfg.PAC)
	}
}

func TestGetHostIPs(t *testing.T) {
	ips := GetHostIPs()
	if len(ips) == 0 {
		t.Fatal("expected IPs")
	}
	found := false
	for _, ip := range ips {
		if ip.String() == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 127.0.0.1")
	}
}

func TestSaveAndReadINI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom", "pxgo.ini")
	cfg, err := ParseArgs([]string{
		"--server=upstream.proxy.com:55112",
		"--pac=http://upstream.proxy.com/PAC.pac",
		"--pac_encoding=latin-1",
		"--port=3131",
		"--listen=100.0.0.11",
		"--gateway=1",
		"--hostonly=1",
		"--allow=127.0.0.1",
		"--noproxy=127.0.0.1",
		"--username=randomuser",
		"--auth=NTLM",
		"--kerberos=1",
		"--workers=100",
		"--threads=100",
		"--idle=100",
		"--socktimeout=35.5",
		"--proxyreload=100",
		"--foreground=1",
		"--log=4",
		"--client_auth=BASIC",
		"--client_nosspi=1",
		"--client_username=randomuser",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveINI(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"server = upstream.proxy.com:55112", "listen = ", "gateway = 1", "kerberos = 1", "client_auth = BASIC", "client_nosspi = 1", "threads = 100"} {
		if !strings.Contains(text, want) {
			t.Fatalf("saved ini missing %q:\n%s", want, text)
		}
	}
	read, err := ReadINI(path)
	if err != nil {
		t.Fatal(err)
	}
	if read.Port != 3131 || read.Server != "upstream.proxy.com:55112" || read.Threads != 100 || !read.Kerberos || !read.ClientNoSSPI {
		t.Fatalf("bad read: %#v", read)
	}
}

func TestReadINIIgnoresInvalidNumericValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pxgo.ini")
	if err := os.WriteFile(path, []byte("[proxy]\nport = not-a-port\n[settings]\nthreads = nope\nsocktimeout = nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadINI(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 3128 || cfg.Threads != 32 || cfg.SockTimeout != 20.0 {
		t.Fatalf("invalid numeric values should preserve defaults: %#v", cfg)
	}
}

func TestParseArgsIgnoresInvalidNumericValues(t *testing.T) {
	cfg, err := ParseArgs([]string{"--port=bad", "--threads=bad", "--socktimeout=bad", "--log=bad"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 3128 || cfg.Threads != 32 || cfg.SockTimeout != 20.0 || cfg.Log != 0 {
		t.Fatalf("invalid numeric CLI values should preserve defaults: %#v", cfg)
	}
}

func TestParseArgsPrecedenceConfigEnvCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pxgo.ini")
	if err := os.WriteFile(path, []byte(`[proxy]
server = file.proxy:8080
port = 1111
listen = 127.0.0.2
auth = BASIC

[settings]
threads = 4
`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PXGO_PORT", "2222")
	t.Setenv("PXGO_THREADS", "8")
	cfg, err := ParseArgs([]string{
		"--config=" + path,
		"--port=3333",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "file.proxy:8080" {
		t.Fatalf("server=%q", cfg.Server)
	}
	if cfg.Port != 3333 {
		t.Fatalf("CLI should win for port, got %d", cfg.Port)
	}
	if cfg.Threads != 8 {
		t.Fatalf("env should win for threads, got %d", cfg.Threads)
	}
	if cfg.Listen != "127.0.0.2" || cfg.Auth != "BASIC" {
		t.Fatalf("config values not loaded: %#v", cfg)
	}
}

func TestParseArgsIgnoresLegacyPXEnvironmentPrefix(t *testing.T) {
	t.Setenv("PX_PORT", "2222")
	t.Setenv("PXGO_PORT", "3333")
	cfg, err := ParseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 3333 {
		t.Fatalf("PXGO_ should be the only recognized application prefix, got port %d", cfg.Port)
	}
}

func TestParseArgsLoadsCWDConfig(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("pxgo.ini", []byte("[proxy]\nport = 4141\nserver = cwd.proxy:80\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 4141 || cfg.Server != "cwd.proxy:80" {
		t.Fatalf("cwd config not loaded: %#v", cfg)
	}
}

func TestParseArgsLoadsDotenvBeforeEnvironmentAndCLI(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("PXGO_PORT=4141\nPXGO_THREADS=7\nPXGO_USERNAME=dotenv-user\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PXGO_THREADS", "9")
	cfg, err := ParseArgs([]string{"--port=5151"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 5151 {
		t.Fatalf("CLI should override dotenv port, got %d", cfg.Port)
	}
	if cfg.Threads != 9 {
		t.Fatalf("environment should override dotenv threads, got %d", cfg.Threads)
	}
	if cfg.Username != "dotenv-user" {
		t.Fatalf("dotenv username not loaded: %#v", cfg)
	}
}

func TestDotenvCanSelectConfigFile(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	ini := filepath.Join(tmp, "from-dotenv.ini")
	if err := os.WriteFile(ini, []byte("[proxy]\nport = 6161\nserver = dotenv.proxy:80\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("PXGO_CONFIG="+ini+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 6161 || cfg.Server != "dotenv.proxy:80" {
		t.Fatalf("dotenv config not loaded: %#v", cfg)
	}
}

func TestExplicitMissingConfigErrorsUnlessSaving(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.ini")
	if _, err := ParseArgs([]string{"--config=" + missing}); err == nil {
		t.Fatal("expected missing explicit config error")
	}
	t.Setenv("PXGO_CONFIG", missing)
	if _, err := ParseArgs(nil); err == nil {
		t.Fatal("expected missing PXGO_CONFIG error")
	}
	t.Setenv("PXGO_SAVE", "1")
	cfg, err := ParseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigPath != missing {
		t.Fatalf("PXGO_SAVE should allow missing PXGO_CONFIG: %#v", cfg)
	}
	t.Setenv("PXGO_CONFIG", "")
	t.Setenv("PXGO_SAVE", "")
	cfg, err = ParseArgs([]string{"--save", "--config=" + missing})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Save || cfg.ConfigPath != missing {
		t.Fatalf("save should allow missing explicit config: %#v", cfg)
	}
}

func TestExplicitConfigPathNormalized(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("custom.ini", []byte("[proxy]\nport = 7171\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseArgs([]string{"--config=custom.ini"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "custom.ini")
	if cfg.ConfigPath != want {
		t.Fatalf("ConfigPath=%q want %q", cfg.ConfigPath, want)
	}
	if got := ConfigPathForSave("nested/pxgo.ini"); got != filepath.Join(tmp, "nested", "pxgo.ini") {
		t.Fatalf("ConfigPathForSave relative=%q", got)
	}
}

func TestParseArgsLoadsScriptDirDotenvFallback(t *testing.T) {
	cwd := t.TempDir()
	scriptDir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	oldExecutablePath := executablePath
	t.Cleanup(func() {
		_ = os.Chdir(oldwd)
		executablePath = oldExecutablePath
	})
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) {
		return filepath.Join(scriptDir, "pxgo"), nil
	}
	if err := os.WriteFile(filepath.Join(scriptDir, ".env"), []byte("PXGO_PORT=6161\nPXGO_USERNAME=script-dotenv\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 6161 || cfg.Username != "script-dotenv" {
		t.Fatalf("script dir dotenv not loaded: %#v", cfg)
	}
}

func TestConfigPathFallsBackToScriptDir(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	cwd := filepath.Join(tmp, "cwd")
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	scriptDir := filepath.Join(tmp, "bin")
	if err := os.Mkdir(scriptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptINI := filepath.Join(scriptDir, "pxgo.ini")
	if err := os.WriteFile(scriptINI, []byte("[proxy]\nport = 7171\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldExecutablePath := executablePath
	executablePath = func() (string, error) { return filepath.Join(scriptDir, "pxgo"), nil }
	t.Cleanup(func() { executablePath = oldExecutablePath })
	if got := ConfigPath(""); got != scriptINI {
		t.Fatalf("got %s want %s", got, scriptINI)
	}
	cfg, err := ParseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 7171 {
		t.Fatalf("script config not loaded: %#v", cfg)
	}
}

func TestConfigPathForSavePrefersWritableExistingLocations(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	cwdINI := filepath.Join(tmp, "pxgo.ini")
	if err := os.WriteFile(cwdINI, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ConfigPathForSave(""); got != cwdINI {
		t.Fatalf("got %s want cwd %s", got, cwdINI)
	}
	if err := os.Remove(cwdINI); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(tmp, "xdg")
	if runtime.GOOS == goosWindows {
		t.Setenv("APPDATA", configDir)
	} else {
		t.Setenv("XDG_CONFIG_HOME", configDir)
	}
	configINI := filepath.Join(configDir, "pxgo", "pxgo.ini")
	if err := os.MkdirAll(filepath.Dir(configINI), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configINI, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ConfigPathForSave(""); got != configINI {
		t.Fatalf("got %s want config %s", got, configINI)
	}
}

func TestPlaintextKeyringStoreAndLoad(t *testing.T) {
	keyring := filepath.Join(t.TempDir(), "keyring.json")
	t.Setenv("PXGO_KEYRING_PLAINTEXT", "1")
	t.Setenv("PXGO_KEYRING_FILE", keyring)
	if err := StorePassword(Realm, "upstream-user", "upstream-pass"); err != nil {
		t.Fatal(err)
	}
	if err := StorePassword(ClientRealm, "client-user", "client-pass"); err != nil {
		t.Fatal(err)
	}
	if got, ok := GetPassword(Realm, "upstream-user"); !ok || got != "upstream-pass" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	cfg, err := ParseArgs([]string{"--username=upstream-user", "--client_username=client-user"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "upstream-pass" || cfg.ClientPassword != "client-pass" {
		t.Fatalf("passwords not loaded: %#v", cfg)
	}
}

func TestGatewayAndHostonlyNormalizeListenAfterAllInputs(t *testing.T) {
	cfg, err := ParseArgs([]string{"--gateway", "--listen=127.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "" {
		t.Fatalf("gateway should clear listen after CLI parsing: %#v", cfg)
	}
	cfg, err = ParseArgs([]string{"--hostonly", "--allow=127.0.0.1", "--listen=127.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "" || cfg.Allow != "" {
		t.Fatalf("hostonly should clear listen and non-gateway allow: %#v", cfg)
	}
	path := filepath.Join(t.TempDir(), "pxgo.ini")
	if err := os.WriteFile(path, []byte("[proxy]\nhostonly = 1\nallow = 127.0.0.1\nlisten = 127.0.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = ReadINI(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "" || cfg.Allow != "" {
		t.Fatalf("ReadINI hostonly dependency mismatch: %#v", cfg)
	}
}

func TestParseArgsBareActions(t *testing.T) {
	cfg, err := ParseArgs([]string{"--restart", "--password", "--client-password", "--test", "--test-auth", "--client-nosspi", "--foreground", "--install", "--uninstall", "--force"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Restart || !cfg.PasswordAction || !cfg.ClientPasswordAction || cfg.Test != "1" || !cfg.TestAuth || !cfg.ClientNoSSPI || !cfg.Foreground || !cfg.Install || !cfg.Uninstall || !cfg.Force {
		t.Fatalf("bare flags not parsed: %#v", cfg)
	}
	cfg, err = ParseArgs([]string{"--verbose"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log != LogStdout || !cfg.Foreground {
		t.Fatalf("verbose should imply stdout log and foreground: %#v", cfg)
	}
	cfg, err = ParseArgs([]string{"--debug"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log != LogScriptDir {
		t.Fatalf("debug log location not parsed: %#v", cfg)
	}
	cfg, err = ParseArgs([]string{"--uniqlog"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log != LogUniqLog {
		t.Fatalf("uniqlog location not parsed: %#v", cfg)
	}
	cfg, err = ParseArgs([]string{"--kerberos", "--log", "--proxyreload"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Kerberos || cfg.Log != 1 || cfg.ProxyReload != 1 {
		t.Fatalf("bare config flags should use value 1: %#v", cfg)
	}
}
