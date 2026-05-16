package pac

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/dop251/goja"
)

type Pac struct {
	location string
	encoding string
	mu       sync.Mutex
	vm       *goja.Runtime
	fn       goja.Callable
}

func New(location, encoding string) *Pac {
	if encoding == "" {
		encoding = "utf-8"
	}
	return &Pac{location: location, encoding: encoding}
}

func (p *Pac) Loaded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fn != nil
}

func (p *Pac) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fn = nil
	p.vm = nil
}

func (p *Pac) loadLocked() {
	if p.fn != nil {
		return
	}
	data, err := p.readPACData()
	if err != nil {
		return
	}
	if p.encoding != "utf-8" && p.encoding != "latin-1" {
		return
	}
	text := string(data)
	if p.encoding == "latin-1" {
		runes := make([]rune, len(data))
		for i, b := range data {
			runes[i] = rune(b)
		}
		text = string(runes)
	}
	vm := goja.New()
	_ = vm.Set("dnsResolve", p.DNSResolve)
	_ = vm.Set("myIpAddress", p.MyIPAddress)
	_ = vm.Set("alert", func(string) {})
	if _, err := vm.RunString(pacUtils + "\n" + text); err != nil {
		return
	}
	val := vm.Get("FindProxyForURL")
	fn, ok := goja.AssertFunction(val)
	if !ok {
		return
	}
	p.vm = vm
	p.fn = fn
}

func (p *Pac) readPACData() ([]byte, error) {
	if strings.HasPrefix(strings.ToLower(p.location), "http://") || strings.HasPrefix(strings.ToLower(p.location), "https://") {
		client := http.Client{}
		resp, err := client.Get(p.location)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("PAC URL returned %s", resp.Status)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(p.location)
}

func (p *Pac) FindProxyForURL(rawurl, host string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loadLocked()
	proxies := "DIRECT"
	if p.fn != nil {
		if out, err := p.fn(goja.Undefined(), p.vm.ToValue(rawurl), p.vm.ToValue(host)); err == nil {
			proxies = out.String()
		}
	}
	replacements := map[string]string{
		"PROXY ":  "",
		"HTTP ":   "",
		"HTTPS ":  "https://",
		"SOCKS4 ": "socks4://",
		"SOCKS5 ": "socks5://",
		"SOCKS ":  "socks5://",
	}
	for old, repl := range replacements {
		proxies = strings.ReplaceAll(proxies, old, repl)
	}
	return strings.ReplaceAll(proxies, ";", ",")
}

func (p *Pac) DNSResolve(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ips[0].String()
}

func (p *Pac) MyIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ip := ipnet.IP.To4(); ip != nil {
			return ip.String()
		}
	}
	return "127.0.0.1"
}

func (p *Pac) String() string {
	return fmt.Sprintf("Pac(%s)", p.location)
}

const pacUtils = `
function dnsDomainIs(host, domain) { return host.length >= domain.length && host.substring(host.length - domain.length) == domain; }
function dnsDomainLevels(host) { return host.split(".").length - 1; }
function isValidIpAddress(ipchars) {
  var matches = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ipchars);
  if (matches == null) return false;
  return !(matches[1] > 255 || matches[2] > 255 || matches[3] > 255 || matches[4] > 255);
}
function convert_addr(ipchars) {
  var bytes = ipchars.split(".");
  return ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16) | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
}
function isInNet(ipaddr, pattern, maskstr) {
  if (!isValidIpAddress(pattern) || !isValidIpAddress(maskstr)) return false;
  if (!isValidIpAddress(ipaddr)) {
    ipaddr = dnsResolve(ipaddr);
    if (ipaddr == null || ipaddr == "") return false;
  }
  var host = convert_addr(ipaddr);
  var pat = convert_addr(pattern);
  var mask = convert_addr(maskstr);
  return (host & mask) == (pat & mask);
}
function shExpMatch(str, shexp) {
  var re = shexp.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + re + '$').test(str);
}
function isPlainHostName(host) { return host.search("(\\.)|:") == -1; }
function isResolvable(host) {
  var ip = dnsResolve(host);
  return ip != null && ip != "";
}
function localHostOrDomainIs(host, hostdom) { return host == hostdom || hostdom.indexOf(host + '.') == 0; }
var wdays = { SUN: 0, MON: 1, TUE: 2, WED: 3, THU: 4, FRI: 5, SAT: 6 };
var months = { JAN: 0, FEB: 1, MAR: 2, APR: 3, MAY: 4, JUN: 5, JUL: 6, AUG: 7, SEP: 8, OCT: 9, NOV: 10, DEC: 11 };
function weekdayRange() {
  function getDay(weekday) { return weekday in wdays ? wdays[weekday] : -1; }
  var date = new Date();
  var argc = arguments.length;
  if (argc < 1) return false;
  var wday;
  if (arguments[argc - 1] == "GMT") { argc--; wday = date.getUTCDay(); } else { wday = date.getDay(); }
  var wd1 = getDay(arguments[0]);
  var wd2 = argc == 2 ? getDay(arguments[1]) : wd1;
  if (wd1 == -1 || wd2 == -1) return false;
  if (wd1 <= wd2) return wd1 <= wday && wday <= wd2;
  return wd2 >= wday || wday >= wd1;
}
function dateRange() {
  function getMonth(name) { return name in months ? months[name] : -1; }
  var date = new Date();
  var argc = arguments.length;
  if (argc < 1) return false;
  var isGMT = arguments[argc - 1] == "GMT";
  if (isGMT) argc--;
  if (argc == 1) {
    var tmp = parseInt(arguments[0]);
    if (isNaN(tmp)) return (isGMT ? date.getUTCMonth() : date.getMonth()) == getMonth(arguments[0]);
    if (tmp < 32) return (isGMT ? date.getUTCDate() : date.getDate()) == tmp;
    return (isGMT ? date.getUTCFullYear() : date.getFullYear()) == tmp;
  }
  var year = date.getFullYear();
  var date1 = new Date(year, 0, 1, 0, 0, 0);
  var date2 = new Date(year, 11, 31, 23, 59, 59);
  var adjustMonth = false;
  for (var i = 0; i < argc >> 1; i++) {
    var left = parseInt(arguments[i]);
    if (isNaN(left)) date1.setMonth(getMonth(arguments[i]));
    else if (left < 32) { adjustMonth = argc <= 2; date1.setDate(left); }
    else date1.setFullYear(left);
  }
  for (var j = argc >> 1; j < argc; j++) {
    var right = parseInt(arguments[j]);
    if (isNaN(right)) date2.setMonth(getMonth(arguments[j]));
    else if (right < 32) date2.setDate(right);
    else date2.setFullYear(right);
  }
  if (adjustMonth) { date1.setMonth(date.getMonth()); date2.setMonth(date.getMonth()); }
  if (isGMT) {
    var tmpDate = date;
    tmpDate.setFullYear(date.getUTCFullYear());
    tmpDate.setMonth(date.getUTCMonth());
    tmpDate.setDate(date.getUTCDate());
    tmpDate.setHours(date.getUTCHours());
    tmpDate.setMinutes(date.getUTCMinutes());
    tmpDate.setSeconds(date.getUTCSeconds());
    date = tmpDate;
  }
  return date1 <= date2 ? date1 <= date && date <= date2 : date2 >= date || date >= date1;
}
function timeRange() {
  var argc = arguments.length;
  var date = new Date();
  var isGMT = false;
  if (argc < 1) return false;
  if (arguments[argc - 1] == "GMT") { isGMT = true; argc--; }
  var hour = isGMT ? date.getUTCHours() : date.getHours();
  var date1 = new Date();
  var date2 = new Date();
  if (argc == 1) return hour == arguments[0];
  if (argc == 2) return arguments[0] <= hour && hour <= arguments[1];
  switch (argc) {
    case 6:
      date1.setSeconds(arguments[2]);
      date2.setSeconds(arguments[5]);
    case 4:
      var middle = argc >> 1;
      date1.setHours(arguments[0]);
      date1.setMinutes(arguments[1]);
      date2.setHours(arguments[middle]);
      date2.setMinutes(arguments[middle + 1]);
      if (middle == 2) date2.setSeconds(59);
      break;
    default:
      throw new Error("timeRange: bad number of arguments");
  }
  if (isGMT) {
    date.setFullYear(date.getUTCFullYear());
    date.setMonth(date.getUTCMonth());
    date.setDate(date.getUTCDate());
    date.setHours(date.getUTCHours());
    date.setMinutes(date.getUTCMinutes());
    date.setSeconds(date.getUTCSeconds());
  }
  return date1 <= date2 ? date1 <= date && date <= date2 : date2 >= date || date >= date1;
}
`
