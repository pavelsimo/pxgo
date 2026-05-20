//go:build kerberos_integration

package kerberos

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestKerberosIntegrationKDC(t *testing.T) {
	principal := os.Getenv("PXGO_KERBEROS_PRINCIPAL")
	password := os.Getenv("PXGO_KERBEROS_PASSWORD")
	if principal == "" || password == "" || os.Getenv("KRB5_CONFIG") == "" {
		t.Skip("set PXGO_KERBEROS_PRINCIPAL, PXGO_KERBEROS_PASSWORD, and KRB5_CONFIG to run KDC integration tests")
	}
	isHeimdal := strings.EqualFold(os.Getenv("PXGO_KERBEROS_FLAVOR"), "heimdal")
	mgr := New(principal, func() *string { return &password }, isHeimdal)
	t.Cleanup(mgr.Cleanup)

	if ok := mgr.KinitWithPassword(); !ok {
		t.Fatalf("kinit failed; backoff=%s", mgr.Backoff)
	}
	if mgr.TicketExpiry.IsZero() || time.Now().After(mgr.TicketExpiry) {
		t.Fatalf("ticket expiry not set to a future time: %s", mgr.TicketExpiry)
	}
	if !mgr.KlistValid() {
		t.Fatal("klist validity check failed after kinit")
	}
	if !mgr.KinitRenew() {
		t.Fatal("kinit renewal failed")
	}
	ccache := strings.TrimPrefix(mgr.CCacheName, "FILE:")
	if _, err := os.Stat(ccache); err != nil {
		t.Fatalf("ccache missing before cleanup: %v", err)
	}
	mgr.Cleanup()
	if _, err := os.Stat(ccache); !os.IsNotExist(err) {
		t.Fatalf("ccache still exists after cleanup: %v", err)
	}
}

func TestKerberosIntegrationWrongPassword(t *testing.T) {
	principal := os.Getenv("PXGO_KERBEROS_PRINCIPAL")
	if principal == "" || os.Getenv("KRB5_CONFIG") == "" {
		t.Skip("set PXGO_KERBEROS_PRINCIPAL and KRB5_CONFIG to run KDC integration tests")
	}
	wrong := "definitely-wrong-password"
	isHeimdal := strings.EqualFold(os.Getenv("PXGO_KERBEROS_FLAVOR"), "heimdal")
	mgr := New(principal, func() *string { return &wrong }, isHeimdal)
	t.Cleanup(mgr.Cleanup)
	if mgr.KinitWithPassword() {
		t.Fatal("kinit unexpectedly succeeded with wrong password")
	}
	if mgr.Backoff == 0 {
		t.Fatal("wrong password should set backoff")
	}
}
