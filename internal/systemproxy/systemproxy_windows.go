//go:build windows

package systemproxy

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const (
	winhttpAutoproxyAutoDetect = 0x00000001
	winhttpAutoproxyConfigURL  = 0x00000002

	winhttpAutoDetectTypeDHCP = 0x00000001
	winhttpAutoDetectTypeDNSA = 0x00000002

	winhttpAccessTypeDefaultProxy = 0
	winhttpAccessTypeNoProxy      = 1
	winhttpAccessTypeNamedProxy   = 3

	winhttpUnableToDownloadScript = 12167
	winhttpAutodetectionFailed    = 12180
)

type winHTTPCurrentUserIEProxyConfig struct {
	AutoDetect    int32
	AutoConfigURL *uint16
	Proxy         *uint16
	ProxyBypass   *uint16
}

type winHTTPAutoProxyOptions struct {
	Flags                 uint32
	AutoDetectFlags       uint32
	AutoConfigURL         *uint16
	Reserved              uintptr
	Reserved2             uint32
	AutoLogonIfChallenged int32
}

type winHTTPProxyInfo struct {
	AccessType  uint32
	Proxy       *uint16
	ProxyBypass *uint16
}

var (
	winhttpDLL = windows.NewLazySystemDLL("winhttp.dll")
	kernelDLL  = windows.NewLazySystemDLL("kernel32.dll")

	procWinHttpGetIEProxyConfigForCurrentUser = winhttpDLL.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procWinHttpOpen                           = winhttpDLL.NewProc("WinHttpOpen")
	procWinHttpGetProxyForURL                 = winhttpDLL.NewProc("WinHttpGetProxyForUrl")
	procWinHttpCloseHandle                    = winhttpDLL.NewProc("WinHttpCloseHandle")
	procGlobalFree                            = kernelDLL.NewProc("GlobalFree")
)

func Discover() Config {
	if cfg, ok := discoverWinHTTPIEProxyConfig(); ok {
		return cfg
	}
	return discoverRegistryProxyConfig()
}

func discoverWinHTTPIEProxyConfig() (Config, bool) {
	var ieConfig winHTTPCurrentUserIEProxyConfig
	ok, _, _ := procWinHttpGetIEProxyConfigForCurrentUser.Call(uintptr(unsafe.Pointer(&ieConfig)))
	if ok == 0 {
		return Config{}, false
	}
	defer globalFreeUTF16(ieConfig.AutoConfigURL)
	defer globalFreeUTF16(ieConfig.Proxy)
	defer globalFreeUTF16(ieConfig.ProxyBypass)

	bypass := windows.UTF16PtrToString(ieConfig.ProxyBypass)
	if ieConfig.AutoDetect != 0 {
		return Config{Found: true, AutoDetect: true, Bypass: bypass}, true
	}
	if pacURL := windows.UTF16PtrToString(ieConfig.AutoConfigURL); pacURL != "" {
		return Config{Found: true, IsPAC: true, PACURL: pacURL, Bypass: bypass}, true
	}
	if proxy := windows.UTF16PtrToString(ieConfig.Proxy); proxy != "" {
		return Config{Found: true, ManualProxy: ParseManualProxyString(proxy), Bypass: bypass}, true
	}
	return Config{}, true
}

func discoverRegistryProxyConfig() Config {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE)
	if err != nil {
		return Config{}
	}
	defer key.Close()
	if pacURL, _, err := key.GetStringValue("AutoConfigURL"); err == nil && pacURL != "" {
		return Config{PACURL: pacURL, Found: true, IsPAC: true}
	}
	enabled, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return Config{}
	}
	proxyServer, _, err := key.GetStringValue("ProxyServer")
	if err != nil || proxyServer == "" {
		return Config{}
	}
	bypass, _, _ := key.GetStringValue("ProxyOverride")
	return Config{ManualProxy: ParseManualProxyString(proxyServer), Bypass: bypass, Found: true}
}

func ResolveProxyForURL(rawurl string, cfg Config) (string, error) {
	if !cfg.AutoDetect && !cfg.IsPAC {
		return "", nil
	}
	agent, _ := windows.UTF16PtrFromString("Px")
	session, _, err := procWinHttpOpen.Call(
		uintptr(unsafe.Pointer(agent)),
		winhttpAccessTypeDefaultProxy,
		0,
		0,
		0,
	)
	if session == 0 {
		return "", err
	}
	defer procWinHttpCloseHandle.Call(session)

	urlp, err := windows.UTF16PtrFromString(rawurl)
	if err != nil {
		return "", err
	}
	var pacURL *uint16
	options := winHTTPAutoProxyOptions{AutoLogonIfChallenged: 1}
	if cfg.IsPAC {
		pacURL, err = windows.UTF16PtrFromString(cfg.PACURL)
		if err != nil {
			return "", err
		}
		options.Flags = winhttpAutoproxyConfigURL
		options.AutoConfigURL = pacURL
	} else {
		options.Flags = winhttpAutoproxyAutoDetect
		options.AutoDetectFlags = winhttpAutoDetectTypeDHCP | winhttpAutoDetectTypeDNSA
	}

	var proxyInfo winHTTPProxyInfo
	ok, _, callErr := procWinHttpGetProxyForURL.Call(
		session,
		uintptr(unsafe.Pointer(urlp)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&proxyInfo)),
	)
	if ok == 0 {
		if errno, ok := callErr.(windows.Errno); ok {
			switch uintptr(errno) {
			case winhttpUnableToDownloadScript, winhttpAutodetectionFailed:
				return "DIRECT", nil
			}
		}
		return "", callErr
	}
	defer globalFreeUTF16(proxyInfo.Proxy)
	defer globalFreeUTF16(proxyInfo.ProxyBypass)

	switch proxyInfo.AccessType {
	case winhttpAccessTypeNamedProxy:
		proxy := windows.UTF16PtrToString(proxyInfo.Proxy)
		if proxy == "" {
			return "", fmt.Errorf("WinHttpGetProxyForUrl returned named proxy without a proxy name")
		}
		return ParseManualProxyString(proxy), nil
	case winhttpAccessTypeNoProxy:
		return "DIRECT", nil
	default:
		return "", fmt.Errorf("WinHttpGetProxyForUrl returned unsupported access type %d", proxyInfo.AccessType)
	}
}

func globalFreeUTF16(ptr *uint16) {
	if ptr != nil {
		procGlobalFree.Call(uintptr(unsafe.Pointer(ptr)))
	}
}
