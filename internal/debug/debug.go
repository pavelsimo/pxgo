package debug

import (
	"fmt"
	"io"
	"os"
	"runtime"
	runtimedebug "runtime/debug"
	"strings"
	"sync"
	"time"
)

type Debug struct {
	mu     sync.Mutex
	name   string
	mode   int
	file   *os.File
	stdout io.Writer
}

var instance *Debug

func Pprint(objs ...any) {
	defer func() { _ = recover() }()
	fmt.Println(objs...)
}

func LogPanic(logPath string, recovered any) {
	msg := fmt.Sprintf("\nPanic: %v\n%s", recovered, runtimedebug.Stack())
	if instance != nil {
		_, _ = instance.Write([]byte(msg))
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
	if instance == nil {
		instance = &Debug{stdout: os.Stdout}
	}
	instance.name = name
	instance.mode = mode
	if instance.stdout == nil {
		instance.stdout = os.Stdout
	}
	return instance, instance.Reopen()
}

func Instance() *Debug {
	return instance
}

func ResetForTest() {
	if instance != nil {
		_ = instance.Close()
	}
	instance = nil
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
		_ = d.file.Sync()
	}
	if d.stdout != nil {
		_, _ = d.stdout.Write(p)
	}
	return len(p), nil
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

func Dprint(msg string) {
	if instance != nil {
		instance.Print(msg)
	}
}
