//go:build !windows

package proxy

import (
	"errors"

	"github.com/pavelsimo/pxgo/internal/config"
)

type sspiAuthSession struct{}

func newSSPISession() (*sspiAuthSession, error) {
	return nil, errors.New("SSPI is only available on Windows")
}

func (s *sspiAuthSession) Negotiate() (string, error) {
	return "", errors.New("SSPI is only available on Windows")
}

func (s *sspiAuthSession) Authenticate(_ string) (string, error) {
	return "", errors.New("SSPI is only available on Windows")
}

func isWindowsSSPICandidate(_ config.Config, _ string) bool {
	return false
}
