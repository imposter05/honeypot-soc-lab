/*
©AngelaMos | 2026
Modified by Hiten, 2026: explicit bind address, connection guard and
shared accept loop; events carry the destination address.

server.go

SMB honeypot service handling NetBIOS negotiate requests

Listens for SMB connections, reads the initial negotiate request,
detects SMB1 versus SMB2, sends a valid negotiate response, and
closes the connection. This negotiate-only approach is sufficient
for logging scanning activity targeting port 445 without the
complexity of full SMB session setup.
*/

package smbd

import (
	"context"
	"encoding/json"
	"net"
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

type SMBService struct {
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
) *SMBService {
	return &SMBService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "smb").Logger(),
		tracker: tracker,
		limiter: limiter,
		guard:   guard,
	}
}

func (s *SMBService) Name() string { return "smb" }

func (s *SMBService) Start(
	ctx context.Context,
) error {
	addr := s.cfg.HoneypotAddr(s.cfg.SMB.Port)
	ln, err := netguard.Listen("smb", addr)
	if err != nil {
		return err
	}
	s.logger.Info().Str("addr", addr).Msg("smb honeypot listening")
	return netguard.Serve(ctx, s.guard.Wrap(ln, "smb"),
		s.cfg.Pipeline.ShutdownGrace, s.logger,
		func(conn net.Conn) { s.handleConnection(conn) })
}

func (s *SMBService) handleConnection(
	conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)
	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceSMB,
		srcIP, srcPort, s.cfg.SMB.Port,
	)
	defer s.tracker.End(sess.ID)

	s.publishConnect(sess, srcIP, srcPort)

	_ = conn.SetReadDeadline(
		time.Now().Add(10 * time.Second),
	)

	data, err := readNBFrame(conn)
	if err != nil {
		return
	}

	version := detectVersion(data)
	if version == 0 {
		return
	}

	dialects := extractDialects(data)
	s.publishScan(sess, srcIP, version, dialects)

	resp := buildNegotiateResponse(version)
	_ = writeNBFrame(conn, resp)
}

func (s *SMBService) publishConnect(
	sess *types.Session,
	srcIP string,
	srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSMB,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestIP:        s.cfg.Network.HoneypotHost,
		DestPort:      s.cfg.SMB.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *SMBService) publishScan(
	sess *types.Session,
	srcIP string,
	version int,
	dialects []string,
) {
	serviceData, _ := json.Marshal(
		map[string]interface{}{
			"smb_version": version,
			"dialects":    dialects,
		},
	)

	s.bus.Publish(config.TopicScan, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSMB,
		EventType:     types.EventScan,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		Tags: []string{
			"smb-negotiate", "mitre:T1595",
		},
		ServiceData: serviceData,
	})
}
