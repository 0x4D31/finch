package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	cblog "github.com/charmbracelet/log"
	"github.com/urfave/cli/v3"

	"github.com/0x4D31/finch/internal/admin"
	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/loader"
	"github.com/0x4D31/finch/internal/rules"
	"github.com/0x4D31/finch/internal/sse"
)

func main() {
	cmd := &cli.Command{
		Name:  "finch",
		Usage: "Finch reverse proxy",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Value:   "info",
				Sources: cli.EnvVars("FINCH_LOG_LEVEL"),
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			switch strings.ToLower(cmd.String("log-level")) {
			case "debug":
				cblog.SetLevel(cblog.DebugLevel)
			case "warn":
				cblog.SetLevel(cblog.WarnLevel)
			case "error":
				cblog.SetLevel(cblog.ErrorLevel)
			default:
				cblog.SetLevel(cblog.InfoLevel)
			}
			return ctx, nil
		},
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "start the finch proxy",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Sources: cli.EnvVars("FINCH_CONFIG")},
					&cli.StringSliceFlag{Name: "listen", Aliases: []string{"l"}, Sources: cli.EnvVars("FINCH_LISTEN"), DefaultText: "0.0.0.0:8443"},
					&cli.StringFlag{Name: "rules", Aliases: []string{"r"}, Sources: cli.EnvVars("FINCH_RULE_FILE")},
					&cli.StringFlag{Name: "upstream", Aliases: []string{"u"}, Value: "http://localhost:8080", Sources: cli.EnvVars("FINCH_UPSTREAM")},
					&cli.StringFlag{Name: "access-log", Aliases: []string{"o"}, Value: "events.jsonl", Sources: cli.EnvVars("FINCH_ACCESS_LOG")},
					&cli.StringFlag{Name: "cert", Aliases: []string{"C"}, Sources: cli.EnvVars("FINCH_CERT")},
					&cli.StringFlag{Name: "key", Aliases: []string{"K"}, Sources: cli.EnvVars("FINCH_KEY")},
					&cli.StringFlag{Name: "upstream-ca-file", Sources: cli.EnvVars("FINCH_UPSTREAM_CA_FILE")},
					&cli.BoolFlag{Name: "upstream-skip-tls-verify", Sources: cli.EnvVars("FINCH_UPSTREAM_SKIP_TLS_VERIFY")},
					&cli.BoolFlag{Name: "enable-admin", Value: true, Sources: cli.EnvVars("FINCH_ENABLE_ADMIN")},
					&cli.StringFlag{Name: "admin-addr", Sources: cli.EnvVars("FINCH_ADMIN_ADDR")},
					&cli.StringFlag{Name: "admin-token", Sources: cli.EnvVars("FINCH_ADMIN_TOKEN")},
					&cli.BoolFlag{Name: "enable-sse", Value: true, Sources: cli.EnvVars("FINCH_ENABLE_SSE")},
					&cli.StringFlag{Name: "sse-addr", Sources: cli.EnvVars("FINCH_SSE_ADDR")},
				},
				Action: serveAction,
			},
			{
				Name:  "echo",
				Usage: "run echo server",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "listen", Aliases: []string{"l"}, Sources: cli.EnvVars("FINCH_LISTEN"), DefaultText: "0.0.0.0:8443"},
				},
				Action: echoAction,
			},
			{
				Name:  "validate",
				Usage: "validate configuration",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Sources: cli.EnvVars("FINCH_CONFIG")},
					&cli.StringFlag{Name: "rules", Sources: cli.EnvVars("FINCH_RULE_FILE")},
				},
				Action: validateAction,
			},
		},
	}

	cmd.ErrWriter = os.Stderr
	cmd.Writer = os.Stderr

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		cblog.Fatal(err.Error())
	}
}

func serveAction(ctx context.Context, cmd *cli.Command) error {
	listenSet := cmd.IsSet("listen")
	configSet := cmd.IsSet("config")

	if listenSet && configSet {
		return errors.New("--config and --listen are mutually exclusive")
	}

	cblog.Infof("starting finch %s", version)

	var cfg config.Config
	var err error
	var cfgPath string

	if configSet || !listenSet {
		cfgPath = cmd.String("config")
		if cfgPath == "" {
			if _, err := os.Stat(defaultConfigFile); err == nil {
				cfgPath = defaultConfigFile
			} else {
				return errors.New("configuration file required")
			}
		}
		cfg, err = loader.LoadMain(cfgPath)
		if err != nil {
			return err
		}
		cblog.Infof("loaded config from %s", cfgPath)
		ov := loader.Overrides{}
		if cmd.IsSet("rules") {
			ov.RuleFile = cmd.String("rules")
			ov.RuleFileSet = true
		}
		if cmd.IsSet("access-log") {
			ov.AccessLog = cmd.String("access-log")
			ov.AccessLogSet = true
		}
		if cmd.IsSet("upstream") {
			ov.Upstream = cmd.String("upstream")
			ov.UpstreamSet = true
		}
		if cmd.IsSet("upstream-ca-file") {
			ov.UpstreamCAFile = cmd.String("upstream-ca-file")
			ov.UpstreamCAFileSet = true
		}
		if cmd.IsSet("upstream-skip-tls-verify") {
			ov.UpstreamSkipTLSVerify = cmd.Bool("upstream-skip-tls-verify")
			ov.UpstreamSkipSet = true
		}
		if cmd.IsSet("enable-admin") {
			ov.AdminEnabled = cmd.Bool("enable-admin")
			ov.AdminEnabledSet = true
		}
		if cmd.IsSet("admin-addr") {
			ov.AdminAddr = cmd.String("admin-addr")
			ov.AdminAddrSet = true
		}
		if cmd.IsSet("admin-token") {
			ov.AdminToken = cmd.String("admin-token")
			ov.AdminTokenSet = true
		}
		if cmd.IsSet("enable-sse") {
			ov.SSEEnabled = cmd.Bool("enable-sse")
			ov.SSEEnabledSet = true
		}
		if cmd.IsSet("sse-addr") {
			ov.SSEAddr = cmd.String("sse-addr")
			ov.SSEAddrSet = true
		}
		if err := loader.Merge(&cfg, ov); err != nil {
			return err
		}
	} else {
		if cmd.String("rules") == "" {
			return errors.New("--rules required when --listen is used")
		}
		cfg, err = loader.SynthesiseFromFlags(cmd)
		if err != nil {
			return err
		}
		cblog.Info("no config file loaded")
	}

	pf := parsedFlags{
		ConfigPath: cfgPath,
		LogLevel:   strings.ToLower(cmd.String("log-level")),
	}
	if cfg.SSE != nil {
		pf.SSEAddr = cfg.SSE.Addr
		pf.SSEEnabled = cfg.SSE.Enabled
	}
	if cfg.Admin != nil {
		pf.AdminAddr = cfg.Admin.Addr
		pf.AdminEnabled = cfg.Admin.Enabled
		pf.AdminToken = cfg.Admin.Token
	}

	var sseSrv *sse.Server
	var hub *sse.Hub
	if pf.SSEEnabled && pf.SSEAddr != "" {
		sseSrv, hub = NewSSEServer(pf.SSEAddr)
		go func() {
			if err := sseSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				cblog.Errorf("sse server: %v", err)
			}
		}()
	}

	var adminSrv *admin.Server

	rt, err := startRuntime(&cfg, pf, hub, &sseSrv, &adminSrv)
	if err != nil {
		return err
	}

	if pf.AdminEnabled && pf.AdminAddr != "" {
		applyFn := func(c config.Config) error {
			cfg = c
			var err error
			rt, err = reloadRuntime(rt, &cfg, pf, hub, &sseSrv, &adminSrv)
			return err
		}
		stopFn := func() { rt.shutdown(pf) }
		adminSrv = admin.New(pf.AdminAddr, pf.AdminToken, &cfg, nil, applyFn, stopFn, pf.ConfigPath)
		rt.adminSrv = adminSrv
		rt.wg.Add(1)
		go func() {
			defer rt.wg.Done()
			if err := adminSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				cblog.Errorf("admin server: %v", err)
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	signal.Stop(sigCh)

	if sseSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = sseSrv.Shutdown(ctx)
		cancel()
	}
	if adminSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = adminSrv.Shutdown(ctx)
		cancel()
	}
	rt.shutdown(pf)
	return nil
}

func echoAction(ctx context.Context, cmd *cli.Command) error {
	listens := cmd.StringSlice("listen")
	if len(listens) == 0 {
		listens = []string{loader.DefaultListenBind}
	}
	if len(listens) > 1 {
		return errors.New("echo supports a single --listen address")
	}

	cfg := config.Config{
		Defaults:  &config.Defaults{ProxyCacheSize: loader.DefaultProxyCacheSize},
		Listeners: []config.ListenerConfig{{ID: "listener1", Bind: listens[0]}},
	}

	pf := parsedFlags{
		LogLevel: strings.ToLower(cmd.String("log-level")),
		EchoMode: true,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	rt, err := startRuntime(&cfg, pf, nil, nil, nil)
	if err != nil {
		signal.Stop(sigCh)
		return err
	}

	<-sigCh
	signal.Stop(sigCh)

	rt.shutdown(pf)
	return nil
}

func validateAction(ctx context.Context, cmd *cli.Command) error {
	cfgSet := cmd.IsSet("config")
	rulesSet := cmd.IsSet("rules")
	if cfgSet == rulesSet {
		return errors.New("specify exactly one of --config or --rules")
	}
	if cfgSet {
		p, err := loader.AbsFromCWD(cmd.String("config"))
		if err != nil {
			return err
		}
		cfg, err := config.Read(p)
		if err != nil {
			return err
		}
		if err := config.Validate(&cfg); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(cmd.ErrWriter, "config valid"); err != nil {
			return err
		}
		return nil
	}
	p, err := loader.AbsFromCWD(cmd.String("rules"))
	if err != nil {
		return err
	}
	if _, err := rules.LoadHCL(p); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(cmd.ErrWriter, "rules valid"); err != nil {
		return err
	}
	return nil
}
