//go:build windows

package proxy

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/alexbrainman/sspi/negotiate"
	"github.com/pavelsimo/pxgo/internal/config"
)

type sspiAuthSession struct {
	ctx          *negotiate.ClientContext
	initialToken []byte
}

// newSSPISession acquires the current Windows user's credentials and initialises
// a Negotiate (Kerberos/NTLM) client context. The initial NEGOTIATE token is
// generated eagerly and stored for the first Negotiate() call.
func newSSPISession() (*sspiAuthSession, error) {
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	ctx, token, err := negotiate.NewClientContext(cred, "")
	if err != nil {
		return nil, err
	}
	return &sspiAuthSession{ctx: ctx, initialToken: token}, nil
}

func (s *sspiAuthSession) Negotiate() (string, error) {
	if len(s.initialToken) == 0 {
		return "", errors.New("SSPI: no initial token available")
	}
	return authSchemeNeg + " " + base64.StdEncoding.EncodeToString(s.initialToken), nil
}

func (s *sspiAuthSession) Authenticate(challengeHeader string) (string, error) {
	_, tokenStr, _ := strings.Cut(strings.TrimSpace(challengeHeader), " ")
	challenge, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tokenStr))
	if err != nil {
		return "", err
	}
	_, outputToken, err := s.ctx.Update(challenge)
	if err != nil {
		return "", err
	}
	s.ctx.Release()
	return authSchemeNeg + " " + base64.StdEncoding.EncodeToString(outputToken), nil
}

// isWindowsSSPICandidate returns true when the current configuration has no
// explicit credentials and the server challenge is a connection-oriented scheme
// (NTLM or Negotiate) that SSPI can satisfy transparently.
func isWindowsSSPICandidate(cfg config.Config, challenge string) bool {
	if cfg.Username != "" || cfg.Password != "" {
		return false
	}
	return isConnectionAuth(authSchemeFromChallenge(challenge))
}
