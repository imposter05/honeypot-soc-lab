/*
Hiten | 2026
steps.go

Protocol clients for scenario steps. Every connection is opened from
the scenario's source address.
*/

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type login struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type step struct {
	SSH *struct {
		login    `yaml:",inline"`
		Commands []string `yaml:"commands"`
	} `yaml:"ssh"`
	SSHLogins *struct {
		Attempts []login `yaml:"attempts"`
	} `yaml:"ssh_logins"`
	SSHForward *struct {
		login  `yaml:",inline"`
		Target string `yaml:"target"`
	} `yaml:"ssh_forward"`
	HTTP *struct {
		Requests []struct {
			Method    string `yaml:"method"`
			Path      string `yaml:"path"`
			UserAgent string `yaml:"user_agent"`
		} `yaml:"requests"`
	} `yaml:"http"`
	FTPUpload *struct {
		login    `yaml:",inline"`
		Filename string `yaml:"filename"`
		Size     int    `yaml:"size"`
	} `yaml:"ftp_upload"`
	Redis *struct {
		Commands [][]string `yaml:"commands"`
	} `yaml:"redis"`
	Touch *struct {
		Services []string `yaml:"services"`
	} `yaml:"touch"`
	MySQL *struct{} `yaml:"mysql"`
	Pause string    `yaml:"pause"`
}

type runner struct {
	sys       *systemInfo
	src       string
	runID     string
	uploadSHA string
}

func (r *runner) dialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(r.src)}}
}

func (r *runner) dial(service string) (net.Conn, error) {
	addr, err := r.sys.addr(service)
	if err != nil {
		return nil, err
	}
	return r.dialer().Dial("tcp", addr)
}

func (r *runner) do(s step) error {
	switch {
	case s.SSH != nil:
		return r.sshSession(s.SSH.login, s.SSH.Commands)
	case s.SSHLogins != nil:
		for _, a := range s.SSHLogins.Attempts {
			// A rejected password is the expected outcome here.
			if c, err := r.sshConnect(a); err == nil {
				_ = c.Close()
			}
			time.Sleep(150 * time.Millisecond)
		}
		return nil
	case s.SSHForward != nil:
		c, err := r.sshConnect(s.SSHForward.login)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		if conn, err := c.Dial("tcp", s.SSHForward.Target); err == nil {
			_ = conn.Close()
			return fmt.Errorf("decoy accepted a forward to %s; it should refuse", s.SSHForward.Target)
		}
		return nil
	case s.HTTP != nil:
		return r.httpRequests(s)
	case s.FTPUpload != nil:
		return r.ftpUpload(s.FTPUpload.login, s.FTPUpload.Filename, s.FTPUpload.Size)
	case s.Redis != nil:
		return r.redis(s.Redis.Commands)
	case s.Touch != nil:
		for _, svc := range s.Touch.Services {
			conn, err := r.dial(svc)
			if err != nil {
				return err
			}
			_ = conn.Close()
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	case s.MySQL != nil:
		conn, err := r.dial("mysql")
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 256)
		if _, err := conn.Read(buf); err != nil {
			return fmt.Errorf("no MySQL greeting: %w", err)
		}
		return nil
	case s.Pause != "":
		d, err := time.ParseDuration(s.Pause)
		if err != nil {
			return err
		}
		time.Sleep(d)
		return nil
	}
	return fmt.Errorf("empty step")
}

func (r *runner) sshConnect(l login) (*ssh.Client, error) {
	addr, err := r.sys.addr("ssh")
	if err != nil {
		return nil, err
	}
	conn, err := r.dialer().Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User: l.User,
		Auth: []ssh.AuthMethod{ssh.Password(l.Password)},
		// The decoy generates its own host key; there is nothing to pin.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // lab decoy
		Timeout:         5 * time.Second,
		ClientVersion:   "SSH-2.0-hlab-labtest",
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func (r *runner) sshSession(l login, commands []string) error {
	c, err := r.sshConnect(l)
	if err != nil {
		return fmt.Errorf("ssh login: %w", err)
	}
	defer func() { _ = c.Close() }()
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		return err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	stdout, _ := sess.StdoutPipe()
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	if err := sess.Shell(); err != nil {
		return err
	}
	time.Sleep(300 * time.Millisecond)
	for _, cmd := range append(commands, "exit") {
		if _, err := fmt.Fprintf(stdin, "%s\r", cmd); err != nil {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

func (r *runner) httpRequests(s step) error {
	addr, err := r.sys.addr("http")
	if err != nil {
		return err
	}
	tr := &http.Transport{DialContext: r.dialer().DialContext, DisableKeepAlives: true}
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, rq := range s.HTTP.Requests {
		m := rq.Method
		if m == "" {
			m = http.MethodGet
		}
		req, err := http.NewRequest(m, "http://"+addr+rq.Path, nil)
		if err != nil {
			return err
		}
		if rq.UserAgent != "" {
			req.Header.Set("User-Agent", rq.UserAgent)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (r *runner) redis(cmds [][]string) error {
	conn, err := r.dial("redis")
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	rd := bufio.NewReader(conn)
	for _, args := range cmds {
		var b strings.Builder
		fmt.Fprintf(&b, "*%d\r\n", len(args))
		for _, a := range args {
			fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
		}
		if _, err := conn.Write([]byte(b.String())); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := rd.ReadString('\n'); err != nil {
			return fmt.Errorf("no reply to %s: %w", args[0], err)
		}
	}
	return nil
}

// ftpUpload is a minimal passive-mode FTP client. The content is
// generated from the run ID so its hash is known in advance.
func (r *runner) ftpUpload(l login, name string, size int) error {
	conn, err := r.dial("ftp")
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	rd := bufio.NewReader(conn)
	expect := func(code string) (string, error) {
		line, err := rd.ReadString('\n')
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(line, code) {
			return line, fmt.Errorf("expected %s, got %q", code, strings.TrimSpace(line))
		}
		return line, nil
	}
	send := func(format string, a ...any) { fmt.Fprintf(conn, format+"\r\n", a...) }

	if _, err := expect("220"); err != nil {
		return err
	}
	send("USER %s", l.User)
	if _, err := expect("331"); err != nil {
		return err
	}
	send("PASS %s", l.Password)
	if _, err := expect("230"); err != nil {
		return err
	}
	send("TYPE I")
	if _, err := expect("200"); err != nil {
		return err
	}
	send("PASV")
	line, err := expect("227")
	if err != nil {
		return err
	}
	open, close := strings.Index(line, "("), strings.Index(line, ")")
	if open < 0 || close < open {
		return fmt.Errorf("bad PASV reply %q", line)
	}
	p := strings.Split(line[open+1:close], ",")
	if len(p) != 6 {
		return fmt.Errorf("bad PASV reply %q", line)
	}
	hi, _ := strconv.Atoi(p[4])
	lo, _ := strconv.Atoi(p[5])
	data, err := r.dialer().Dial("tcp", net.JoinHostPort(strings.Join(p[:4], "."), strconv.Itoa(hi*256+lo)))
	if err != nil {
		return fmt.Errorf("data connection: %w", err)
	}
	send("STOR %s", name)
	if _, err := expect("150"); err != nil {
		_ = data.Close()
		return err
	}
	content := make([]byte, size)
	seed := []byte("hlab-labtest-" + r.runID + "-" + r.src)
	for i := range content {
		content[i] = seed[i%len(seed)]
	}
	_, werr := data.Write(content)
	_ = data.Close()
	if werr != nil {
		return werr
	}
	if _, err := expect("226"); err != nil {
		return err
	}
	send("QUIT")
	sum := sha256.Sum256(content)
	r.uploadSHA = hex.EncodeToString(sum[:])
	return nil
}
