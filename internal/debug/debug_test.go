package debug

import (
	"os"
	"path/filepath"
	"strings"
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
