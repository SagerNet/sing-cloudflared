package cmd

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	cloudflared "github.com/sagernet/sing-cloudflared"
	"github.com/sagernet/sing-cloudflared/pkg/icmp"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"github.com/spf13/cobra"
)

var (
	commandRunFlagToken           string
	commandRunFlagHAConnections   int
	commandRunFlagProtocol        string
	commandRunFlagPostQuantum     bool
	commandRunFlagEdgeIPVersion   int
	commandRunFlagDatagramVersion string
	commandRunFlagGracePeriod     time.Duration
	commandRunFlagRegion          string
	commandRunFlagLogLevel        string

	commandRunNewService = func(options cloudflared.ServiceOptions) (serviceRunner, error) {
		return cloudflared.NewService(options)
	}
	commandRunNewSignals = func() chan os.Signal {
		return make(chan os.Signal, 1)
	}
	commandRunNotifySignals = func(ch chan<- os.Signal, signals ...os.Signal) {
		signal.Notify(ch, signals...)
	}
	commandRunStopSignals = func(ch chan<- os.Signal) {
		signal.Stop(ch)
	}
	commandRunExit              = os.Exit
	commandRunAfterStart        = func() {}
	commandRunStartCloseMonitor = func(ctx context.Context) {
		go closeMonitor(ctx)
	}
)

type serviceRunner interface {
	Start() error
	Close() error
}

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run the tunnel",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandRun.Flags().StringVarP(&commandRunFlagToken, "token", "t", "", "tunnel token (or set CF_TUNNEL_TOKEN)")
	commandRun.Flags().IntVar(&commandRunFlagHAConnections, "ha-connections", 0, "number of HA connections (default 4)")
	commandRun.Flags().StringVarP(&commandRunFlagProtocol, "protocol", "p", "", "transport protocol (auto, quic, http2)")
	commandRun.Flags().BoolVar(&commandRunFlagPostQuantum, "post-quantum", false, "enable post-quantum cryptography (QUIC only)")
	commandRun.Flags().IntVar(&commandRunFlagEdgeIPVersion, "edge-ip-version", 0, "edge IP version (0=auto, 4, 6)")
	commandRun.Flags().StringVar(&commandRunFlagDatagramVersion, "datagram-version", "", "datagram protocol version (v2, v3)")
	commandRun.Flags().DurationVar(&commandRunFlagGracePeriod, "grace-period", 0, "graceful shutdown period (default 30s)")
	commandRun.Flags().StringVar(&commandRunFlagRegion, "region", "", "Cloudflare edge region")
	commandRun.Flags().StringVar(&commandRunFlagLogLevel, "log-level", "info", "log level (trace, debug, info, warn, error)")
	mainCommand.AddCommand(commandRun)
}

func run() error {
	token := commandRunFlagToken
	if token == "" {
		token = os.Getenv("CF_TUNNEL_TOKEN")
	}
	if token == "" {
		return E.New("missing token: provide --token or set CF_TUNNEL_TOKEN")
	}

	logLevel, err := parseLogLevel(commandRunFlagLogLevel)
	if err != nil {
		return E.Cause(err, "parse log level")
	}
	serviceLogger := newLogger(logLevel)

	service, err := commandRunNewService(cloudflared.ServiceOptions{
		Logger:           serviceLogger,
		ConnectionDialer: N.SystemDialer,
		ICMPHandler:      icmp.NewDirectHandler(serviceLogger),
		Token:            token,
		HAConnections:    commandRunFlagHAConnections,
		Protocol:         commandRunFlagProtocol,
		PostQuantum:      commandRunFlagPostQuantum,
		EdgeIPVersion:    commandRunFlagEdgeIPVersion,
		DatagramVersion:  commandRunFlagDatagramVersion,
		GracePeriod:      commandRunFlagGracePeriod,
		Region:           commandRunFlagRegion,
	})
	if err != nil {
		return E.Cause(err, "create service")
	}

	osSignals := commandRunNewSignals()
	commandRunNotifySignals(osSignals, os.Interrupt, syscall.SIGTERM)
	startCtx, startDone := context.WithCancel(context.Background())
	go func() {
		select {
		case <-osSignals:
			service.Close()
			commandRunExit(1)
		case <-startCtx.Done():
		}
	}()

	err = service.Start()
	startDone()
	if err != nil {
		service.Close()
		return E.Cause(err, "start service")
	}

	commandRunAfterStart()
	<-osSignals
	commandRunStopSignals(osSignals)
	serviceLogger.Info("shutting down...")

	closeCtx, closeDone := context.WithCancel(context.Background())
	commandRunStartCloseMonitor(closeCtx)
	service.Close()
	closeDone()
	return nil
}

const closeMonitorTimeout = 10 * time.Second

func closeMonitor(ctx context.Context) {
	time.Sleep(closeMonitorTimeout)
	select {
	case <-ctx.Done():
		return
	default:
	}
	log.Fatal("cloudflared did not close!")
}
