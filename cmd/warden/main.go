package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fmt"

	"github.com/rsturla/warden/internal/ca"
	"github.com/rsturla/warden/internal/config"
	"github.com/rsturla/warden/internal/dns"
	"github.com/rsturla/warden/internal/health"
	"github.com/rsturla/warden/internal/listener"
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/proxy"
	"github.com/rsturla/warden/internal/secrets"
	"github.com/rsturla/warden/internal/telemetry"
	"github.com/rsturla/warden/internal/version"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("warden %s (commit: %s, built: %s)\n", version.Version, version.Commit, version.Date)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(*configPath, logger); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// CA
	var wardenCA ca.CertProvider
	if cfg.CA.Cert != "" && cfg.CA.Key != "" {
		wardenCA, err = ca.NewExternalCA(cfg.CA.Cert, cfg.CA.Key)
	} else {
		wardenCA, err = ca.NewAutoCA(cfg.CA.CertOutput)
	}
	if err != nil {
		return err
	}

	// Secrets
	var sources []secrets.SecretSource
	for _, s := range cfg.Secrets {
		src, err := secrets.Build(s)
		if err != nil {
			return err
		}
		sources = append(sources, src)
	}
	chain := secrets.NewChain(sources...)

	// DNS
	var baseResolver dns.Resolver
	if cfg.DNS.DoT.Enabled {
		baseResolver = dns.NewDoTResolver(cfg.DNS.DoT.Server)
	} else {
		baseResolver = dns.NewStdlibResolver(cfg.DNS.Servers)
	}
	var dnsResolver dns.Resolver = baseResolver
	if cfg.DNS.Cache.Enabled {
		dnsResolver = dns.NewCachingResolver(baseResolver, time.Duration(cfg.DNS.Cache.MaxTTL)*time.Second)
	}

	denylist, err := dns.NewDenylist(cfg.DNS.DenyResolvedIPs)
	if err != nil {
		return err
	}

	// Policy
	engine, err := policy.NewEngine(cfg.Policies)
	if err != nil {
		return err
	}

	// Telemetry
	slogExporter := telemetry.NewSlogExporter(logger)
	var exporter telemetry.TelemetryExporter = slogExporter
	if cfg.Telemetry.Traces.Enabled || cfg.Telemetry.Metrics.Enabled {
		otelExp := telemetry.NewOTELExporter(telemetry.OTELConfig{
			TracesEndpoint:  cfg.Telemetry.Traces.Endpoint,
			MetricsEndpoint: cfg.Telemetry.Metrics.Endpoint,
			TracesEnabled:   cfg.Telemetry.Traces.Enabled,
			MetricsEnabled:  cfg.Telemetry.Metrics.Enabled,
		})
		exporter = telemetry.NewMultiExporter(slogExporter, otelExp)
	}

	// Proxy
	p := proxy.New(proxy.Config{
		CA:        wardenCA,
		Policy:    engine,
		Secrets:   chain,
		Resolver:  dnsResolver,
		Denylist:  denylist,
		Telemetry: exporter,
	})

	// Health
	healthSrv := health.New()

	// Listeners
	proxyListener, err := listener.New(cfg.Server.Listen)
	if err != nil {
		return err
	}
	healthListener, err := listener.New(cfg.Server.HealthListen)
	if err != nil {
		return err
	}

	logger.Info("warden starting",
		"listen", cfg.Server.Listen,
		"health_listen", cfg.Server.HealthListen,
		"policies", len(cfg.Policies),
		"secret_sources", len(cfg.Secrets),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	proxySrv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	healthHTTP := &http.Server{
		Handler:           healthSrv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)

	go func() { errCh <- proxySrv.Serve(proxyListener) }()
	go func() { errCh <- healthHTTP.Serve(healthListener) }()

	healthSrv.SetReady(true)
	logger.Info("warden ready")

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errCh:
		logger.Error("server error", "error", err)
		cancel()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("proxy shutdown error", "error", err)
	}
	if err := healthHTTP.Shutdown(shutdownCtx); err != nil {
		logger.Error("health shutdown error", "error", err)
	}
	if err := exporter.Close(shutdownCtx); err != nil {
		logger.Error("telemetry close error", "error", err)
	}

	return nil
}
