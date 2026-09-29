/*
©AngelaMos | 2026
Modified by Hiten, 2026: rewritten for local use. No Redis; checks
the schema version before starting; writes the sensor row; loads and
records the rule set; wires the ordered processor, cases, response
playbook and connection guard; prints a plain startup summary; and
shuts down in order (listeners, then queue drain, then database).

serve.go
*/

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/CarterPerez-dev/hive/internal/api"
	"github.com/CarterPerez-dev/hive/internal/cases"
	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/detection"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ftpd"
	"github.com/CarterPerez-dev/hive/internal/geo"
	"github.com/CarterPerez-dev/hive/internal/httpd"
	"github.com/CarterPerez-dev/hive/internal/intel"
	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/internal/mysqld"
	"github.com/CarterPerez-dev/hive/internal/netguard"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/redisd"
	"github.com/CarterPerez-dev/hive/internal/response"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/internal/smbd"
	"github.com/CarterPerez-dev/hive/internal/sshd"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the decoy services, pipeline and dashboard",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context())
		},
	}
}

func runServe(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	logger := buildLogger(cfg)

	for _, d := range []string{cfg.Paths.DataDir, cfg.Paths.HostKeys, cfg.Paths.Replays,
		cfg.Paths.Uploads, cfg.Paths.Exports, cfg.Paths.LabRuns} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", d, err)
		}
	}

	pg, err := store.NewPgxStore(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("%w\n\nIs PostgreSQL running? Run `hive doctor` or scripts/setup-local.sh", err)
	}
	defer pg.Close()

	schema, err := pg.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("reading migration version (have migrations been run?): %w\n\nRun `hive migrate up`", err)
	}
	if schema < config.RequiredMigration {
		return fmt.Errorf("database is at migration %d but this build needs %d; run `hive migrate up`",
			schema, config.RequiredMigration)
	}
	if err := pg.EnsurePartitions(ctx); err != nil {
		return err
	}

	var svcNames []string
	for _, l := range cfg.Listeners() {
		if l.Enabled && l.Name != "api" {
			svcNames = append(svcNames, l.Name)
		}
	}
	hostname, _ := os.Hostname()
	if err := pg.UpsertSensor(ctx, &types.Sensor{
		ID: cfg.Sensor.ID, Hostname: hostname, Region: cfg.Sensor.Region,
		Services: svcNames, StartedAt: time.Now().UTC(), Status: "active",
	}); err != nil {
		return err
	}

	rules, rulesSource, err := detection.LoadRules(cfg.Detection.RulesFile)
	if err != nil {
		return err
	}
	engine := detection.NewEngine(rules)
	if err := pg.SyncRules(ctx, ruleRows(rules)); err != nil {
		return err
	}

	geoLookup, err := geo.NewLookup(cfg.GeoIP.DBPath)
	if err != nil {
		logger.Warn().Err(err).Msg("continuing without GeoIP")
		geoLookup, _ = geo.NewLookup("")
	}
	defer func() { _ = geoLookup.Close() }()

	bus := event.NewBus(cfg.Pipeline.QueueSize, cfg.Pipeline.EnqueueWait, &logger)
	broadcaster := event.NewBroadcaster(cfg.Pipeline.LiveBuffer)
	tracker := session.NewTracker()
	limiter := ratelimit.NewIPLimiter(
		rate.Limit(cfg.Limits.ConnectionRatePerIP), cfg.Limits.ConnectionBurstPerIP)
	defer limiter.Stop()

	// Session rows are written from the tracker callbacks. They use
	// a background context so the final update still runs while
	// the application is stopping.
	dbCtx := context.Background()
	tracker.SetOnStart(func(sess types.Session) {
		c, cancel := context.WithTimeout(dbCtx, 5*time.Second)
		defer cancel()
		if err := pg.InsertSession(c, &sess, cfg.Network.HoneypotHost); err != nil {
			logger.Error().Err(err).Str("session_id", sess.ID).Msg("session start not stored")
		}
	})
	tracker.SetOnEnd(func(sess types.Session) {
		c, cancel := context.WithTimeout(dbCtx, 5*time.Second)
		defer cancel()
		if err := pg.UpdateSession(c, &sess); err != nil {
			logger.Error().Err(err).Str("session_id", sess.ID).Msg("session end not stored")
		}
	})

	deny := response.NewDenylist()
	guard := netguard.New(deny, cfg.Limits.MaxConnectionsPerService,
		cfg.Limits.IdleTimeout, cfg.Limits.MaxSessionDuration,
		deniedPublisher(cfg, bus))

	resp := response.NewManager(pg, deny, cfg, logger.With().Str("component", "response").Logger(),
		response.LiveProber(cfg, func(service string) uint64 {
			return guard.Stats()[service].Denied
		}))
	if err := resp.Load(ctx); err != nil {
		return fmt.Errorf("loading active restrictions: %w", err)
	}
	caseMgr := cases.NewManager(pg, cfg.Cases.CorrelationWindow, resp.OnSeverityChange)

	deps := event.ProcessorDeps{
		Bus: bus, Store: pg, Engine: engine,
		Extractor: intel.NewExtractor(), Cases: caseMgr, Broadcaster: broadcaster,
		Logger: logger.With().Str("component", "processor").Logger(),
		Config: cfg, LabRanges: cfg.LabPrefixes(), Sessions: tracker,
		SpoolPath: filepath.Join(cfg.Paths.DataDir, "spool", "failed-events.jsonl"),
	}
	if geoLookup.Enabled() {
		deps.Geo = geoLookup
	}
	proc := event.NewProcessor(deps)

	services, err := buildServices(cfg, bus, &logger, tracker, limiter, guard)
	if err != nil {
		return err
	}
	apiSrv := api.New(api.Deps{
		Store: pg, Bus: bus, Processor: proc, Broadcaster: broadcaster,
		Engine: engine, RulesSource: rulesSource, Response: resp, Guard: guard,
		Tracker: tracker, Mitre: mitre.NewIndex(), Config: cfg, Logger: &logger,
		ServiceState: func() map[string]string {
			open := netguard.Listening()
			out := map[string]string{}
			for _, s := range append(svcNames, "api") {
				if _, ok := open[s]; ok {
					out[s] = "listening"
				} else {
					out[s] = "not listening"
				}
			}
			return out
		},
	})

	printSummary(cfg, schema, rulesSource, len(rules), geoLookup.Enabled())

	// The processor gets its own context so queued events are still
	// written after the listeners stop.
	procCtx, procCancel := context.WithCancel(context.Background())
	defer procCancel()
	procDone := make(chan struct{})
	go func() {
		defer close(procDone)
		_ = proc.Run(procCtx)
	}()

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return resp.Run(gctx) })
	for _, svc := range append(services, types.Service(apiSrv)) {
		svc := svc
		g.Go(func() error {
			if err := svc.Start(gctx); err != nil {
				return fmt.Errorf("%s stopped: %w", svc.Name(), err)
			}
			return nil
		})
	}
	runErr := g.Wait()

	logger.Info().Msg("listeners stopped; writing queued events")
	bus.Close()
	select {
	case <-procDone:
	case <-time.After(cfg.Pipeline.DrainTimeout):
		procCancel()
		<-procDone
		logger.Warn().Msg("drain timeout reached; remaining events were written to the spool file")
	}
	st := proc.Stats()
	logger.Info().Uint64("stored", st.Processed).Uint64("failed", st.PersistFailures).
		Uint64("dropped", bus.Stats().Dropped).Msg("stopped")

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

func ruleRows(rs []*detection.Rule) []store.RuleRow {
	out := make([]store.RuleRow, 0, len(rs))
	for _, r := range rs {
		def, _ := json.Marshal(r)
		out = append(out, store.RuleRow{ID: r.ID, Version: r.Version, Name: r.Name,
			Enabled: r.Enabled, Definition: def})
	}
	return out
}

// deniedPublisher records connections closed by the denylist, so an
// analyst can confirm that an approved restriction is working.
func deniedPublisher(cfg *config.Config, bus *event.Bus) netguard.DeniedFunc {
	return func(service string, src, dst netip.AddrPort) {
		svc, ok := types.ParseServiceType(service)
		if !ok {
			return
		}
		data, _ := json.Marshal(map[string]string{"reason": "application denylist"})
		bus.Publish(config.TopicConnect, &types.Event{
			ID:            uuid.Must(uuid.NewV7()).String(),
			SessionID:     "denied-" + uuid.Must(uuid.NewV7()).String(),
			SensorID:      cfg.Sensor.ID,
			Timestamp:     time.Now().UTC(),
			ServiceType:   svc,
			EventType:     types.EventConnectionDenied,
			SourceIP:      src.Addr().Unmap().String(),
			SourcePort:    int(src.Port()),
			DestIP:        dst.Addr().Unmap().String(),
			DestPort:      int(dst.Port()),
			Protocol:      types.ProtocolTCP,
			SchemaVersion: config.SchemaVersion,
			ServiceData:   data,
		})
	}
}

func printSummary(cfg *config.Config, schema int64, rulesSource string, nRules int, geoOn bool) {
	var decoys []string
	for _, l := range cfg.Listeners() {
		if !l.Enabled || l.Name == "api" {
			continue
		}
		d := fmt.Sprintf("%s %d", l.Name, l.Port)
		if l.Name == "ftp" {
			d += fmt.Sprintf(" (passive %d-%d)", cfg.FTP.PassivePortMin, cfg.FTP.PassivePortMax)
		}
		decoys = append(decoys, d)
	}
	geoText := "off (no database configured; locations are not shown)"
	if geoOn {
		geoText = cfg.GeoIP.DBPath
	}
	fmt.Printf("\n%s %s\n", config.ToolTitle, config.ToolVersion)
	fmt.Printf("  Config     %s\n", cfg.Source)
	fmt.Printf("  Dashboard  http://%s\n", cfg.ManagementAddr())
	fmt.Printf("  Decoys     %s on %s\n", strings.Join(decoys, ", "), cfg.Network.HoneypotHost)
	fmt.Printf("  SSH auth   %s\n", cfg.SSH.AuthMode)
	fmt.Printf("  Database   %s (migration %d)\n", redactDSN(cfg.Database.DSN), schema)
	fmt.Printf("  Rules      %d from %s\n", nRules, rulesSource)
	fmt.Printf("  GeoIP      %s\n", geoText)
	fmt.Printf("  Data       %s\n", cfg.Paths.DataDir)
	if a, err := netip.ParseAddr(cfg.Network.HoneypotHost); err == nil && !a.IsLoopback() {
		fmt.Printf("\n  Warning: decoys listen on %s, which other machines may reach.\n", a)
	}
	fmt.Println()
}

func redactDSN(dsn string) string {
	if i := strings.Index(dsn, "://"); i >= 0 {
		if at := strings.LastIndex(dsn, "@"); at > i {
			creds := dsn[i+3 : at]
			if c := strings.Index(creds, ":"); c >= 0 {
				return dsn[:i+3] + creds[:c] + ":***" + dsn[at:]
			}
		}
	}
	return dsn
}

func buildLogger(cfg *config.Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.Log.Level)
	if err != nil || cfg.Log.Level == "" {
		level = zerolog.InfoLevel
	}
	if flagVerbose {
		level = zerolog.DebugLevel
	}
	if cfg.Log.JSONFormat {
		return zerolog.New(os.Stdout).Level(level).With().Timestamp().Logger()
	}
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).
		Level(level).With().Timestamp().Logger()
}

func buildServices(
	cfg *config.Config, bus *event.Bus, logger *zerolog.Logger,
	tracker *session.Tracker, limiter *ratelimit.IPLimiter, guard *netguard.Guard,
) ([]types.Service, error) {
	var services []types.Service
	if cfg.SSH.Enabled {
		hostkey, err := sshd.LoadOrGenerateHostKey(cfg.SSH.HostKeyPath)
		if err != nil {
			return nil, fmt.Errorf("ssh host key %s: %w", cfg.SSH.HostKeyPath, err)
		}
		services = append(services, sshd.New(cfg, bus, logger, tracker, limiter, hostkey, guard))
	}
	if cfg.HTTP.Enabled {
		services = append(services, httpd.New(cfg, bus, logger, tracker, limiter, guard))
	}
	if cfg.FTP.Enabled {
		services = append(services, ftpd.New(cfg, bus, logger, tracker, limiter, guard))
	}
	if cfg.SMB.Enabled {
		services = append(services, smbd.New(cfg, bus, logger, tracker, limiter, guard))
	}
	if cfg.MySQL.Enabled {
		services = append(services, mysqld.New(cfg, bus, logger, tracker, limiter, guard))
	}
	if cfg.Redis.Enabled {
		services = append(services, redisd.New(cfg, bus, logger, tracker, limiter, guard))
	}
	return services, nil
}
