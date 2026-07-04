package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// relay pumps bytes between the two ends of a CONNECT tunnel. Both conns stay
// raw (no reader wrappers) so io.Copy can use zero-copy paths (splice on
// Linux); idle detection is done with read deadlines instead. On a clean EOF
// only the destination's write side is closed, so the opposite direction can
// keep draining in-flight data (TCP half-close).
func relay(a, b net.Conn, idle time.Duration) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		if copyDirection(dst, src, idle, &lastActivity) {
			halfClose(dst)
			return
		}
		// Real error or idle expiry: tear the whole tunnel down.
		_ = a.Close()
		_ = b.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// copyDirection copies src to dst until EOF, a real error, or tunnel-wide idle
// expiry. It reports whether the copy ended in a clean EOF. When idle > 0 each
// io.Copy call is bounded by a read deadline; on timeout the direction only
// gives up once the tunnel as a whole has been silent for the idle interval.
func copyDirection(dst, src net.Conn, idle time.Duration, lastActivity *atomic.Int64) bool {
	if idle <= 0 {
		_, err := io.Copy(dst, src)
		return err == nil
	}
	// Both directions' deadlines fire at the same instant, so a quiet
	// direction can observe staleness a moment before the active one records
	// its progress. A single short re-check closes that window.
	grace := idle / 10
	if grace > 100*time.Millisecond {
		grace = 100 * time.Millisecond
	}
	graced := false
	wait := idle
	for {
		_ = src.SetReadDeadline(time.Now().Add(wait))
		n, err := io.Copy(dst, src)
		if n > 0 {
			lastActivity.Store(time.Now().UnixNano())
		}
		if err == nil {
			return true // EOF
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return false
		}
		if time.Since(time.Unix(0, lastActivity.Load())) < idle {
			graced = false
			wait = idle
			continue
		}
		if !graced {
			graced = true
			wait = grace
			continue
		}
		return false // tunnel idle
	}
}

type closeWriter interface{ CloseWrite() error }

func halfClose(c net.Conn) {
	if cw, ok := c.(closeWriter); ok { // *net.TCPConn and *tls.Conn
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
