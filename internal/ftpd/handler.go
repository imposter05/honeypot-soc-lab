/*
©AngelaMos | 2026
Modified by Hiten, 2026: passive data listeners bind to the
configured honeypot host and port range instead of every interface
on a random port, the data connection must come from the control
connection's address, and uploads are hashed while streaming, capped
at limits.max_upload_bytes, and written to the uploads directory
under their SHA-256 name. Upstream read up to 1 MiB and discarded it.

handler.go

FTP command handler and data channel management for the honeypot

Implements the FTP control protocol with USER/PASS authentication,
PASV data channels for directory listings, and STOR upload capture
written to the uploads directory. Presents a realistic ProFTPD environment
with fake directory listings that mirror an Ubuntu server layout.
*/

package ftpd

import (
	"bufio"
	"crypto/md5" //nolint:gosec // MD5 is recorded for matching against feeds, not for security
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	stateInit = iota
	stateUser
	stateAuth
)

type ftpConn struct {
	ctrl       net.Conn
	reader     *bufio.Reader
	state      int
	username   string
	cwd        string
	binary     bool
	dataListen net.Listener
	opts       ftpOptions
}

// ftpOptions come from the config.
type ftpOptions struct {
	passiveHost string
	passiveMin  int
	passiveMax  int
	maxUpload   int64
	uploadDir   string
}

// uploadResult describes one STOR.
type uploadResult struct {
	size        int64
	sha256      string
	md5         string
	truncated   bool
	storagePath string
	err         string
}

func newFTPConn(conn net.Conn) *ftpConn {
	return &ftpConn{
		ctrl:   conn,
		reader: bufio.NewReader(conn),
		cwd:    "/",
	}
}

func (f *ftpConn) reply(code int, msg string) {
	fmt.Fprintf(f.ctrl, "%d %s\r\n", code, msg)
}

func (f *ftpConn) readLine() (string, string, error) {
	line, err := f.reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])

	arg := ""
	if len(parts) > 1 {
		arg = parts[1]
	}

	return cmd, arg, nil
}

func (f *ftpConn) close() {
	if f.dataListen != nil {
		_ = f.dataListen.Close()
	}
}

type cmdResult struct {
	cmd      string
	arg      string
	quit     bool
	password string
	upload   *uploadResult
	filename string
}

func (f *ftpConn) dispatch(
	cmd, arg string,
) cmdResult {
	res := cmdResult{cmd: cmd, arg: arg}

	switch cmd {
	case "USER":
		f.username = arg
		f.state = stateUser
		f.reply(
			331, "Password required for "+arg,
		)

	case "PASS":
		f.state = stateAuth
		f.reply(
			230, "User "+f.username+" logged in",
		)
		res.password = arg

	case "SYST":
		f.reply(215, "UNIX Type: L8")

	case "FEAT":
		fmt.Fprintf(
			f.ctrl,
			"211-Features:\r\n"+
				" PASV\r\n"+
				" UTF8\r\n"+
				" SIZE\r\n"+
				"211 End\r\n",
		)

	case "PWD", "XPWD":
		f.reply(
			257,
			fmt.Sprintf(`"%s"`, f.cwd),
		)

	case "CWD", "XCWD":
		target := resolveFTPPath(arg, f.cwd)
		f.cwd = target
		f.reply(250, "CWD command successful")

	case "CDUP":
		f.cwd = parentFTPPath(f.cwd)
		f.reply(250, "CWD command successful")

	case "TYPE":
		f.binary = strings.ToUpper(arg) == "I"
		f.reply(200, "Type set")

	case "PASV":
		f.openPASV()

	case "LIST", "NLST":
		f.sendListing()

	case "RETR":
		if f.dataListen != nil {
			_ = f.dataListen.Close()
			f.dataListen = nil
		}
		f.reply(
			550,
			arg+": No such file or directory",
		)

	case "STOR":
		if up := f.recvUpload(); up != nil {
			res.upload = up
			res.filename = arg
		}

	case "SIZE":
		f.reply(550, arg+": No such file")

	case "MDTM":
		f.reply(550, arg+": No such file")

	case "MKD", "XMKD":
		f.reply(
			257,
			fmt.Sprintf(`"%s" created`, arg),
		)

	case "RMD", "XRMD", "DELE":
		f.reply(250, "OK")

	case "RNFR":
		f.reply(350, "Awaiting new name")

	case "RNTO":
		f.reply(250, "Rename successful")

	case "NOOP":
		f.reply(200, "OK")

	case "HELP":
		f.reply(214, "No help available")

	case "QUIT":
		f.reply(221, "Goodbye")
		res.quit = true

	default:
		f.reply(502, "Command not implemented")
	}

	return res
}

func (f *ftpConn) openPASV() {
	if f.dataListen != nil {
		_ = f.dataListen.Close()
		f.dataListen = nil
	}

	host := f.opts.passiveHost
	ip := net.ParseIP(host).To4()
	if ip == nil {
		f.reply(425, "Cannot open data connection")
		return
	}
	for port := f.opts.passiveMin; port <= f.opts.passiveMax; port++ {
		l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		f.dataListen = l
		f.reply(227, fmt.Sprintf(
			"Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
			ip[0], ip[1], ip[2], ip[3], port/256, port%256,
		))
		return
	}
	f.reply(425, "No passive port free")
}

func (f *ftpConn) acceptData() net.Conn {
	if f.dataListen == nil {
		return nil
	}
	defer func() {
		_ = f.dataListen.Close()
		f.dataListen = nil
	}()

	tcpL, ok := f.dataListen.(*net.TCPListener)
	if !ok {
		return nil
	}
	_ = tcpL.SetDeadline(
		time.Now().Add(10 * time.Second),
	)

	dc, err := f.dataListen.Accept()
	if err != nil {
		return nil
	}
	// Only the client on the control connection may use the data
	// port. Another host racing to connect gets nothing.
	ctrlIP, _, _ := net.SplitHostPort(f.ctrl.RemoteAddr().String())
	dataIP, _, _ := net.SplitHostPort(dc.RemoteAddr().String())
	if ctrlIP != dataIP {
		_ = dc.Close()
		return nil
	}
	return dc
}

func (f *ftpConn) sendListing() {
	if f.dataListen == nil {
		f.reply(425, "Use PASV first")
		return
	}

	f.reply(150, "Opening data connection")

	dc := f.acceptData()
	if dc == nil {
		f.reply(
			425, "Cannot open data connection",
		)
		return
	}

	_, _ = fmt.Fprint(dc, fakeDirListing(f.cwd))
	_ = dc.Close()

	f.reply(226, "Transfer complete")
}

func (f *ftpConn) recvUpload() *uploadResult {
	if f.dataListen == nil {
		f.reply(425, "Use PASV first")
		return nil
	}

	f.reply(150, "Opening data connection")

	dc := f.acceptData()
	if dc == nil {
		f.reply(425, "Cannot open data connection")
		return nil
	}
	defer func() { _ = dc.Close() }()
	_ = dc.SetReadDeadline(time.Now().Add(60 * time.Second))

	res := &uploadResult{}
	tmp, err := os.CreateTemp(f.opts.uploadDir, "upload-*.part")
	if err != nil {
		res.err = "cannot create upload file: " + err.Error()
	}
	h256, h5 := sha256.New(), md5.New()
	var sink io.Writer = io.MultiWriter(h256, h5)
	if tmp != nil {
		sink = io.MultiWriter(h256, h5, tmp)
	}

	n, _ := io.Copy(sink, io.LimitReader(dc, f.opts.maxUpload))
	res.size = n
	// One more byte means the client sent more than the limit.
	extra, _ := io.CopyN(io.Discard, dc, 1)
	res.truncated = extra > 0

	res.sha256 = hex.EncodeToString(h256.Sum(nil))
	res.md5 = hex.EncodeToString(h5.Sum(nil))

	if tmp != nil {
		_ = tmp.Close()
		final := filepath.Join(f.opts.uploadDir, res.sha256+".bin")
		if err := os.Rename(tmp.Name(), final); err != nil {
			_ = os.Remove(tmp.Name())
			res.err = "cannot store upload: " + err.Error()
		} else {
			_ = os.Chmod(final, 0o400)
			res.storagePath = final
		}
	}

	f.reply(226, "Transfer complete")
	return res
}

func fakeDirListing(cwd string) string {
	now := time.Now()
	month := now.AddDate(0, -1, 0).Format("Jan 02 15:04")
	old := now.AddDate(0, -6, 0).Format("Jan 02 15:04")

	lines := []string{
		fmt.Sprintf(
			"drwxr-xr-x 2 root root 4096 %s .",
			month,
		),
		fmt.Sprintf(
			"drwxr-xr-x 3 root root 4096 %s ..",
			month,
		),
	}

	if cwd == "/" {
		lines = append(lines,
			fmt.Sprintf(
				"drwxr-xr-x 2 root root 4096 %s bin",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 5 root root 4096 %s etc",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 3 root root 4096 %s home",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 2 root root 4096 %s tmp",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 8 root root 4096 %s var",
				month,
			),
			fmt.Sprintf(
				"-rw-r--r-- 1 root root  220 %s .bashrc",
				old,
			),
		)
	}

	return strings.Join(lines, "\r\n") + "\r\n"
}

func resolveFTPPath(path, cwd string) string {
	if strings.HasPrefix(path, "/") {
		return cleanFTPPath(path)
	}
	if cwd == "/" {
		return cleanFTPPath("/" + path)
	}
	return cleanFTPPath(cwd + "/" + path)
}

func parentFTPPath(path string) string {
	if path == "/" {
		return "/"
	}
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return "/"
	}
	return strings.Join(parts[:len(parts)-1], "/")
}

func cleanFTPPath(path string) string {
	parts := strings.Split(path, "/")
	var clean []string
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			if len(clean) > 0 {
				clean = clean[:len(clean)-1]
			}
			continue
		}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return "/"
	}
	return "/" + strings.Join(clean, "/")
}
