package winstartup

import "testing"

func TestBuildRunCommandUsesWindowlessVariant(t *testing.T) {
	got, err := BuildRunCommand(`C:\Program Files\Pxgo\pxgo.exe`, `C:\Users\Test\pxgo.ini`, func(path string) bool {
		return path == `C:\Program Files\Pxgo\pxgow.exe`
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `"C:\Program Files\Pxgo\pxgow.exe" --config=C:\Users\Test\pxgo.ini`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestBuildRunCommandQuotesConfigPath(t *testing.T) {
	got, err := BuildRunCommand(`C:\Pxgo\pxgo.exe`, `C:\Users\Test User\pxgo.ini`, func(path string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	want := `C:\Pxgo\pxgow.exe "--config=C:\Users\Test User\pxgo.ini"`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestBuildRunCommandMissingPxgow(t *testing.T) {
	if _, err := BuildRunCommand(`C:\Pxgo\pxgo.exe`, `C:\pxgo.ini`, func(path string) bool { return false }); err == nil {
		t.Fatal("expected missing pxgow error")
	}
}

func TestBuildRunCommandNonStandardExecutable(t *testing.T) {
	got, err := BuildRunCommand(`C:\Tools\custom.exe`, `C:\pxgo.ini`, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `C:\Tools\custom.exe --config=C:\pxgo.ini`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
