package netguard

import (
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type denyAll struct{ ip netip.Addr }

func (d denyAll) Denied(ip netip.Addr, _ string) bool { return ip == d.ip }

func listen(t *testing.T, g *Guard) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wl := g.Wrap(ln, "test")
	go func() {
		for {
			c, err := wl.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = c.Write([]byte("hello\n"))
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestDeniedSourceIsClosed(t *testing.T) {
	var called atomic.Int32
	g := New(denyAll{netip.MustParseAddr("127.0.0.1")}, 4, time.Second, time.Minute,
		func(string, netip.AddrPort, netip.AddrPort) { called.Add(1) })
	ln := listen(t, g)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 16)
	n, err := c.Read(b)
	if n != 0 || err == nil {
		t.Fatalf("expected closed connection, read %q err %v", b[:n], err)
	}
	time.Sleep(50 * time.Millisecond)
	if called.Load() != 1 || g.Stats()["test"].Denied != 1 {
		t.Fatalf("denied callback=%d stats=%+v", called.Load(), g.Stats()["test"])
	}
}

func TestConnectionLimit(t *testing.T) {
	g := New(nil, 1, time.Second, time.Minute, nil)
	ln := listen(t, g)
	first, _ := net.Dial("tcp", ln.Addr().String())
	defer func() { _ = first.Close() }()
	buf := make([]byte, 6)
	_, _ = io.ReadFull(first, buf)
	second, _ := net.Dial("tcp", ln.Addr().String())
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := second.Read(buf); n != 0 {
		t.Fatal("second connection should be closed while the first is open")
	}
	time.Sleep(50 * time.Millisecond)
	if g.Stats()["test"].OverLimit != 1 {
		t.Fatalf("over limit not counted: %+v", g.Stats()["test"])
	}
}

func TestIdleTimeoutClosesConnection(t *testing.T) {
	g := New(nil, 4, 100*time.Millisecond, time.Minute, nil)
	ln := listen(t, g)
	c, _ := net.Dial("tcp", ln.Addr().String())
	buf := make([]byte, 6)
	_, _ = io.ReadFull(c, buf)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	_, err := c.Read(buf)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("server should close an idle connection quickly, err=%v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if g.Stats()["test"].Active != 0 {
		t.Fatalf("active count not released: %+v", g.Stats()["test"])
	}
}
