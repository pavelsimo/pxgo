package debug

import (
	"fmt"
	"io"
	"os"
	"runtime"
	runtimedebug "runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Debug struct {
	mu     sync.Mutex
	name   string
	mode   int
	file   *os.File
	stdout io.Writer
}

var instance atomic.Pointer[Debug]

func Pprint(objs ...any) {
	defer func() { _ = recover() }()
	fmt.Println(objs...)
}

func LogPanic(logPath string, recovered any) {
	msg := fmt.Sprintf("\nPanic: %v\n%s", recovered, runtimedebug.Stack())
	if d := instance.Load(); d != nil {
		_, _ = d.Write([]byte(msg))
		d.sync() // panic forensics must reach disk
		return
	}
	_, _ = os.Stderr.Write([]byte(msg))
	if logPath != "" {
		_ = os.WriteFile(logPath, []byte(msg), 0o600)
	}
}

func New(name string, appendMode bool) (*Debug, error) {
	mode := os.O_CREATE | os.O_WRONLY
	if appendMode {
		mode |= os.O_APPEND
	} else {
		mode |= os.O_TRUNC
	}
	d := instance.Load()
	if d == nil {
		d = &Debug{stdout: os.Stdout}
	}
	d.mu.Lock()
	d.name = name
	d.mode = mode
	if d.stdout == nil {
		d.stdout = os.Stdout
	}
	d.mu.Unlock()
	instance.Store(d)
	return d, d.Reopen()
}

func Instance() *Debug {
	return instance.Load()
}

func ResetForTest() {
	if d := instance.Load(); d != nil {
		_ = d.Close()
	}
	instance.Store(nil)
}

func (d *Debug) Reopen() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
	if d.name == "" {
		return nil
	}
	f, err := os.OpenFile(d.name, d.mode, 0o644)
	if err != nil {
		return err
	}
	d.file = f
	return nil
}

func (d *Debug) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil
	}
	err := d.file.Close()
	d.file = nil
	return err
}

func (d *Debug) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file != nil {
		_, _ = d.file.Write(p)
	}
	if d.stdout != nil {
		_, _ = d.stdout.Write(p)
	}
	return len(p), nil
}

func (d *Debug) sync() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file != nil {
		_ = d.file.Sync()
	}
}

func (d *Debug) Print(msg string) {
	tree := make([]string, 0, 3)
	for i := 2; i < 5; i++ {
		pc, _, _, ok := runtime.Caller(i)
		if !ok {
			break
		}
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}
		parts := strings.Split(fn.Name(), ".")
		tree = append(tree, parts[len(parts)-1])
	}
	_, _ = fmt.Fprintf(d, "%d: /%s: %s\n", time.Now().Unix(), strings.Join(tree, "/"), msg)
}

func (d *Debug) GetPrint() func(string) {
	return d.Print
}

// Enabled reports whether debug logging is active. Callers with expensive
// message construction should check it (or use Dprintf) so disabled logging
// costs a single atomic load.
func Enabled() bool {
	return instance.Load() != nil
}

func Dprint(msg string) {
	if d := instance.Load(); d != nil {
		d.Print(msg)
	}
}

// Dprintf formats lazily: when logging is disabled the arguments are never
// formatted, keeping hot paths allocation-free.
func Dprintf(format string, args ...any) {
	if d := instance.Load(); d != nil {
		d.Print(fmt.Sprintf(format, args...))
	}
}
