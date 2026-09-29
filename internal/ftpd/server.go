/*
©AngelaMos | 2026
Modified by Hiten, 2026: explicit bind address and connection guard,
events carry ports and destination, upload events carry hashes and
the stored file path.

server.go

FTP honeypot service accepting file transfer client connections

Emulates a ProFTPD 1.3.8b server with accept-all authentication.
Logs every credential attempt, command, and uploaded file to the
event bus. PASV mode data channels are opened on demand for
directory listings and upload capture.
*/

package ftpd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/netguard"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type FTPService struct {
	cfg     *config.Config
	bus     *event.Bus
	logger  zerolog.Logger
	tracker *session.Tracker
	limiter *ratelimit.IPLimiter
	guard   *netguard.Guard
}

func New(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
	guard *netguard.Guard,
) *FTPService {
	return &FTPService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "ftp").Logger(),
		tracker: tracker,
		limiter: limiter,
		guard:   guard,
	}
}

func (s *FTPService) Name() string { return "ftp" }

func (s *FTPService) Start(ctx context.Context) error {
	addr := s.cfg.HoneypotAddr(s.cfg.FTP.Port)
	ln, err := netguard.Listen("ftp", addr)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.cfg.Paths.Uploads, 0o700); err != nil {
		_ = ln.Close()
		return fmt.Errorf("ftp: creating uploads directory: %w", err)
	}
	s.logger.Info().Str("addr", addr).
		Str("passive_ports", fmt.Sprintf("%d-%d", s.cfg.FTP.PassivePortMin, s.cfg.FTP.PassivePortMax)).
		Msg("ftp honeypot listening")
	return netguard.Serve(ctx, s.guard.Wrap(ln, "ftp"),
		s.cfg.Pipeline.ShutdownGrace, s.logger,
		func(conn net.Conn) { s.handleConnection(ctx, conn) })
}

func (s *FTPService) handleConnection(
	ctx context.Context, conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)
	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceFTP,
		srcIP, srcPort, s.cfg.FTP.Port,
	)
	defer s.tracker.End(sess.ID)

	s.publishConnect(sess, srcIP, srcPort)
	defer s.publishDisconnect(sess, srcIP, srcPort)

	fc := newFTPConn(conn)
	fc.opts = ftpOptions{
		passiveHost: s.cfg.FTP.PassiveHost,
		passiveMin:  s.cfg.FTP.PassivePortMin,
		passiveMax:  s.cfg.FTP.PassivePortMax,
		maxUpload:   s.cfg.Limits.MaxUploadBytes,
		uploadDir:   s.cfg.Paths.Uploads,
	}
	defer fc.close()

	fmt.Fprintf(
		fc.ctrl, "%s\r\n", s.cfg.FTP.Banner,
	)

	for {
		if ctx.Err() != nil {
			return
		}

		cmd, arg, err := fc.readLine()
		if err != nil {
			return
		}

		result := fc.dispatch(cmd, arg)

		// The password is already in the login event; do not repeat
		// it in the command log.
		logArg := arg
		if cmd == "PASS" {
			logArg = "********"
		}
		s.publishCommand(sess, srcIP, srcPort, cmd, logArg)

		if cmd == "PASS" {
			s.publishAuth(
				sess, srcIP, srcPort,
				fc.username, result.password,
			)
			s.tracker.SetLogin(
				sess.ID, true, fc.username, "",
			)
		}

		if result.upload != nil {
			s.publishUpload(
				sess, srcIP, srcPort,
				result.filename, result.upload,
			)
		}

		if result.quit {
			return
		}
	}
}

func (s *FTPService) base(sess *types.Session, srcIP string, srcPort int, et types.EventType) *types.Event {
	return &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceFTP,
		EventType:     et,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestIP:        s.cfg.Network.HoneypotHost,
		DestPort:      s.cfg.FTP.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	}
}

func (s *FTPService) publishConnect(sess *types.Session, srcIP string, srcPort int) {
	s.bus.Publish(config.TopicConnect, s.base(sess, srcIP, srcPort, types.EventConnect))
}

func (s *FTPService) publishDisconnect(sess *types.Session, srcIP string, srcPort int) {
	s.bus.Publish(config.TopicDisconnect, s.base(sess, srcIP, srcPort, types.EventDisconnect))
}

// publishAuth records a login. The FTP decoy accepts every login.
func (s *FTPService) publishAuth(sess *types.Session, srcIP string, srcPort int, username, password string) {
	ev := s.base(sess, srcIP, srcPort, types.EventLoginSuccess)
	ev.ServiceData, _ = json.Marshal(map[string]string{
		"username": username, "password": password,
		"auth_method": "password", "auth_mode": "accept-all",
	})
	s.bus.Publish(config.TopicAuth, ev)
}

func (s *FTPService) publishCommand(sess *types.Session, srcIP string, srcPort int, cmd, arg string) {
	ev := s.base(sess, srcIP, srcPort, types.EventCommand)
	ev.ServiceData, _ = json.Marshal(map[string]string{"command": cmd, "arg": truncate(arg, 1024)})
	s.bus.Publish(config.TopicCommand, ev)
}

func (s *FTPService) publishUpload(sess *types.Session, srcIP string, srcPort int, filename string, up *uploadResult) {
	ev := s.base(sess, srcIP, srcPort, types.EventFileUpload)
	ev.Tags = []string{"file-upload"}
	ev.ServiceData, _ = json.Marshal(map[string]any{
		"filename":     truncate(filename, 512),
		"size":         up.size,
		"sha256":       up.sha256,
		"md5":          up.md5,
		"truncated":    up.truncated,
		"size_limit":   s.cfg.Limits.MaxUploadBytes,
		"storage_path": up.storagePath,
		"store_error":  up.err,
	})
	s.bus.Publish(config.TopicFile, ev)
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
