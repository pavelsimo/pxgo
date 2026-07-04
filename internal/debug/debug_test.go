package debug

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDprintNoopWithoutDebug(t *testing.T) {
	ResetForTest()
	Dprint("no output expected")
}

func TestDebugSingleton(t *testing.T) {
	ResetForTest()
	first, err := New("", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New("", false)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("New should return the singleton debug instance")
	}
}

func TestDebugWritesAndReopens(t *testing.T) {
	ResetForTest()
	logfile := filepath.Join(t.TempDir(), "debug.log")
	d, err := New(logfile, false)
	if err != nil {
		t.Fatal(err)
	}
	Dprint("first")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Reopen(); err != nil {
		t.Fatal(err)
	}
	d.Print("second")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logfile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "second") || !strings.Contains(text, "/") {
		t.Fatalf("unexpected log: %q", text)
	}
}

func TestDebugGetPrint(t *testing.T) {
	ResetForTest()
	logfile := filepath.Join(t.TempDir(), "getprint.log")
	d, err := New(logfile, false)
	if err != nil {
		t.Fatal(err)
	}
	print := d.GetPrint()
	print("via get print")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logfile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "via get print") {
		t.Fatalf("unexpected log: %q", data)
	}
}

func TestLogPanicWritesFileWithoutDebug(t *testing.T) {
	ResetForTest()
	logfile := filepath.Join(t.TempDir(), "debug-main.log")
	LogPanic(logfile, "boom")
	data, err := os.ReadFile(logfile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Panic: boom") || !strings.Contains(text, "goroutine") {
		t.Fatalf("unexpected panic log: %q", text)
	}
}

func TestDebugConcurrentInitAndPrint(t *testing.T) {
	ResetForTest()
	logfile := filepath.Join(t.TempDir(), "race.log")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				switch g % 3 {
				case 0:
					if _, err := New(logfile, true); err != nil {
						t.Errorf("New: %v", err)
						return
					}
				case 1:
					Dprint("concurrent")
				default:
					Dprintf("concurrent %d", i)
				}
			}
		}(g)
	}
	wg.Wait()
	ResetForTest()
}

func TestDprintfNoopWithoutDebug(t *testing.T) {
	ResetForTest()
	if Enabled() {
		t.Fatal("Enabled should be false without an instance")
	}
	Dprintf("no output expected %d", 1)
}

func TestDprintfWritesWhenEnabled(t *testing.T) {
	ResetForTest()
	logfile := filepath.Join(t.TempDir(), "dprintf.log")
	d, err := New(logfile, false)
	if err != nil {
		t.Fatal(err)
	}
	if !Enabled() {
		t.Fatal("Enabled should be true after New")
	}
	Dprintf("value=%d", 42)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logfile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "value=42") {
		t.Fatalf("unexpected log: %q", data)
	}
	ResetForTest()
}
