/*
©AngelaMos | 2026
Modified by Hiten, 2026: explicit bind address and connection guard,
optional test-credentials mode that rejects unknown pairs, auth
events carry ports and auth mode, the session goroutine now ends
with the channel instead of waiting for server shutdown, and
port-forward requests are recorded as requests instead of as
lateral movement.

server.go

SSH honeypot service accepting all authentication attempts

Emulates an OpenSSH server with accept-all password and public key
callbacks. After authentication, provides an interactive shell with
a fake filesystem and command execution. Logs every connection,
credential attempt, and session to the event bus. Uses the SSH
server version banner from config to avoid honeypot fingerprinting.
*/

package sshd

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/netguard"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type SSHService struct {
	cfg     *config.Config
	bus     *event.Bus
	logger  zerolog.Logger
	tracker *session.Tracker
	limiter *ratelimit.IPLimiter
	hostkey ssh.Signer
	guard   *netguard.Guard
}

func New(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
	hostkey ssh.Signer,
	guard *netguard.Guard,
) *SSHService {
	return &SSHService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "ssh").Logger(),
		tracker: tracker,
		limiter: limiter,
		hostkey: hostkey,
		guard:   guard,
	}
}

func (s *SSHService) Name() string { return "ssh" }

func (s *SSHService) Start(ctx context.Context) error {
	addr := s.cfg.HoneypotAddr(s.cfg.SSH.Port)
	ln, err := netguard.Listen("ssh", addr)
	if err != nil {
		return err
	}
	s.logger.Info().Str("addr", addr).Str("auth_mode", s.cfg.SSH.AuthMode).
		Msg("ssh honeypot listening")
	return netguard.Serve(ctx, s.guard.Wrap(ln, "ssh"),
		s.cfg.Pipeline.ShutdownGrace, s.logger,
		func(conn net.Conn) { s.handleConnection(ctx, conn) })
}

// checkPassword applies the configured auth mode.
func (s *SSHService) checkPassword(user, pass string) bool {
	if s.cfg.SSH.AuthMode != config.SSHAuthTestCredentials {
		return true
	}
	for _, c := range s.cfg.SSH.TestCredentials {
		if subtle.ConstantTimeCompare([]byte(c.Username), []byte(user)) == 1 &&
			subtle.ConstantTimeCompare([]byte(c.Password), []byte(pass)) == 1 {
			return true
		}
	}
	return false
}

func (s *SSHService) handleConnection(
	ctx context.Context, conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)

	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceSSH,
		srcIP, srcPort, s.cfg.SSH.Port,
	)
	defer s.tracker.End(sess.ID)

	s.tracker.SetAuthMode(sess.ID, s.cfg.SSH.AuthMode)
	s.publishConnect(sess, srcIP, srcPort)

	var lastUsername string

	sshCfg := &ssh.ServerConfig{
		ServerVersion: s.cfg.SSH.Banner,
		MaxAuthTries:  20,
		PasswordCallback: func(
			c ssh.ConnMetadata, pass []byte,
		) (*ssh.Permissions, error) {
			ok := s.checkPassword(c.User(), string(pass))
			s.publishAuth(sess.ID, srcIP, srcPort, c.User(),
				string(pass), "password", string(c.ClientVersion()), ok)
			if !ok {
				return nil, errAuthRejected
			}
			lastUsername = c.User()
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(
			c ssh.ConnMetadata, key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			// Public keys are accepted only in accept-all mode.
			ok := s.cfg.SSH.AuthMode != config.SSHAuthTestCredentials
			s.publishAuthKey(sess.ID, srcIP, srcPort, c.User(),
				ssh.FingerprintSHA256(key), string(c.ClientVersion()), ok)
			if !ok {
				return nil, errAuthRejected
			}
			lastUsername = c.User()
			return &ssh.Permissions{}, nil
		},
	}

	sshCfg.AddHostKey(s.hostkey)

	sshConn, chans, reqs, err := ssh.NewServerConn(
		conn, sshCfg,
	)
	if err != nil {
		s.publishDisconnect(sess, srcIP, srcPort)
		return
	}
	defer func() { _ = sshConn.Close() }()

	s.tracker.SetLogin(
		sess.ID, true, lastUsername,
		string(sshConn.ClientVersion()),
	)

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			go s.handleSession(
				ctx, newChan, sess, srcIP, lastUsername,
			)
		case "direct-tcpip":
			s.logPortForward(sess, srcIP, srcPort, newChan)
			_ = newChan.Reject(
				ssh.Prohibited, "not allowed",
			)
		default:
			_ = newChan.Reject(
				ssh.UnknownChannelType, "unknown",
			)
		}
	}

	s.publishDisconnect(sess, srcIP, srcPort)
}

type sessionState struct {
	ch       ssh.Channel
	sess     *types.Session
	srcIP    string
	username string
	cols     int
	rows     int
	recorder *session.Recorder
}

func (s *SSHService) handleSession(
	ctx context.Context,
	newChan ssh.NewChannel,
	sess *types.Session,
	srcIP string,
	username string,
) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()

	st := &sessionState{
		ch:       ch,
		sess:     sess,
		srcIP:    srcIP,
		username: username,
		cols:     80,
		rows:     24,
	}

	st.recorder = session.NewRecorder(
		sess.ID, srcIP, s.cfg.Sensor.ID,
		st.cols, st.rows,
	)

	// Upstream blocked here until the whole server stopped, which
	// left one goroutine per finished session. Now the goroutine
	// ends when the channel's requests end or the server stops.
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.dispatchRequests(reqs, st)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		_ = ch.Close()
		<-done
	}
}

func (s *SSHService) dispatchRequests(
	reqs <-chan *ssh.Request, st *sessionState,
) {
	for req := range reqs {
		if s.handleSessionRequest(req, st) {
			// Drain so the ssh library is not blocked on us.
			go ssh.DiscardRequests(reqs)
			return
		}
	}
}

func (s *SSHService) handleSessionRequest(
	req *ssh.Request, st *sessionState,
) bool {
	switch req.Type {
	case "pty-req":
		if len(req.Payload) > 4 {
			st.cols, st.rows = parsePTYRequest(
				req.Payload,
			)
			st.recorder.Resize(st.cols, st.rows)
		}

	case "shell":
		replyOK(req)
		RunShell(
			st.ch, st.sess.ID, s.cfg.Sensor.ID,
			st.srcIP, st.username,
			s.cfg.SSH.Hostname,
			s.bus, st.recorder, st.cols, st.rows,
			s.eventBase(st.sess),
		)
		s.saveRecording(st)
		_ = st.ch.Close()
		return true

	case "exec":
		replyOK(req)
		cmd := parseExecPayload(req.Payload)
		s.handleExec(
			st.ch, st.sess, st.srcIP,
			st.username, cmd, st.recorder,
		)
		_ = st.ch.Close()
		return true

	case "window-change":
		if len(req.Payload) >= 8 {
			st.cols, st.rows = parseWindowChange(
				req.Payload,
			)
			st.recorder.Resize(st.cols, st.rows)
		}
	}

	replyOK(req)
	return false
}

func replyOK(req *ssh.Request) {
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

func (s *SSHService) saveRecording(st *sessionState) {
	if _, err := st.recorder.Save(s.cfg.Paths.Replays); err != nil {
		s.logger.Error().Err(err).
			Str("session_id", st.sess.ID).
			Msg("failed to save session recording")
	}
}

func (s *SSHService) handleExec(
	ch ssh.Channel,
	sess *types.Session,
	srcIP string,
	username string,
	cmd string,
	recorder *session.Recorder,
) {
	recorder.WriteInput([]byte(cmd + "\n"))

	publishCommand(
		s.bus, sess.ID, s.cfg.Sensor.ID, srcIP,
		cmd, s.cfg.SSH.Hostname, s.eventBase(sess),
	)

	fs := NewFakeFS(s.cfg.SSH.Hostname)
	cmdCtx := &CommandContext{
		FS:       fs,
		Hostname: s.cfg.SSH.Hostname,
		Username: username,
		CWD:      "/root",
	}

	output := DispatchCommand(cmd, cmdCtx)
	if output != "" {
		_, _ = ch.Write([]byte(output))
		recorder.WriteOutput([]byte(output))
	}

	_, _ = ch.SendRequest(
		"exit-status", false, []byte{0, 0, 0, 0},
	)
}

// logPortForward records a refused direct-tcpip request. The target
// host and port come from the request payload.
func (s *SSHService) logPortForward(
	sess *types.Session,
	srcIP string,
	srcPort int,
	newChan ssh.NewChannel,
) {
	target := parseDirectTCPIP(newChan.ExtraData())
	serviceData, _ := json.Marshal(map[string]string{
		"channel_type": newChan.ChannelType(),
		"target":       target,
		"result":       "refused",
	})
	ev := s.eventBase(sess)
	ev.EventType = types.EventExploit
	ev.Tags = []string{"port-forward-request"}
	ev.ServiceData = serviceData
	s.bus.Publish(config.TopicCommand, ev)
}

// parseDirectTCPIP reads "host:port" from an RFC 4254 7.2 payload.
func parseDirectTCPIP(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 || len(b) < 8+n {
		return ""
	}
	host := string(b[4 : 4+n])
	p := b[4+n:]
	port := int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// eventBase fills the fields every SSH event shares.
func (s *SSHService) eventBase(sess *types.Session) *types.Event {
	return &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		SourceIP:      sess.SourceIP,
		SourcePort:    sess.SourcePort,
		DestIP:        s.cfg.Network.HoneypotHost,
		DestPort:      s.cfg.SSH.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	}
}

func (s *SSHService) publishConnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestIP:        s.cfg.Network.HoneypotHost,
		DestPort:      s.cfg.SSH.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *SSHService) publishDisconnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicDisconnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     types.EventDisconnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestIP:        s.cfg.Network.HoneypotHost,
		DestPort:      s.cfg.SSH.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

var errAuthRejected = errors.New("authentication rejected")

func (s *SSHService) authEvent(sessionID, srcIP string, srcPort int, ok bool, data map[string]string) {
	data["auth_mode"] = s.cfg.SSH.AuthMode
	serviceData, _ := json.Marshal(data)
	et := types.EventLoginSuccess
	if !ok {
		et = types.EventLoginFailed
	}
	s.bus.Publish(config.TopicAuth, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     et,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestIP:        s.cfg.Network.HoneypotHost,
		DestPort:      s.cfg.SSH.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *SSHService) publishAuth(
	sessionID, srcIP string, srcPort int,
	username, password, method, clientVersion string, ok bool,
) {
	s.authEvent(sessionID, srcIP, srcPort, ok, map[string]string{
		"username":       username,
		"password":       password,
		"auth_method":    method,
		"client_version": clientVersion,
	})
}

func (s *SSHService) publishAuthKey(
	sessionID, srcIP string, srcPort int,
	username, fingerprint, clientVersion string, ok bool,
) {
	s.authEvent(sessionID, srcIP, srcPort, ok, map[string]string{
		"username":       username,
		"public_key":     fingerprint,
		"auth_method":    "publickey",
		"client_version": clientVersion,
	})
}

func parsePTYRequest(payload []byte) (int, int) {
	if len(payload) < 8 {
		return 80, 24
	}

	termLen := int(payload[3]) | int(payload[2])<<8 |
		int(payload[1])<<16 | int(payload[0])<<24
	offset := 4 + termLen

	if len(payload) < offset+8 {
		return 80, 24
	}

	cols := int(payload[offset+3]) | int(payload[offset+2])<<8 |
		int(payload[offset+1])<<16 | int(payload[offset])<<24
	rows := int(payload[offset+7]) | int(payload[offset+6])<<8 |
		int(payload[offset+5])<<16 | int(payload[offset+4])<<24

	return cols, rows
}

func parseWindowChange(payload []byte) (int, int) {
	if len(payload) < 8 {
		return 80, 24
	}

	cols := int(payload[3]) | int(payload[2])<<8 |
		int(payload[1])<<16 | int(payload[0])<<24
	rows := int(payload[7]) | int(payload[6])<<8 |
		int(payload[5])<<16 | int(payload[4])<<24

	return cols, rows
}

func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}

	cmdLen := int(payload[3]) | int(payload[2])<<8 |
		int(payload[1])<<16 | int(payload[0])<<24

	if len(payload) < 4+cmdLen {
		return ""
	}

	return string(payload[4 : 4+cmdLen])
}
