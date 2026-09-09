// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// outrelay-relay is the stateless relay data plane. It dials the
// controller's gRPC registry on startup, self-registers (UpsertRelay),
// and routes service registrations / resolves through it. The relay
// keeps a local URI -> connected-agent map so it can open
// INCOMING_STREAM toward the right QUIC connection.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/observe"
	"github.com/boanlab/OutRelay/lib/transport"

	"github.com/boanlab/outrelay-relay/pkg/forward"

	"github.com/boanlab/outrelay-relay/pkg/audit"
	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/intra"
	"github.com/boanlab/outrelay-relay/pkg/policy"
	relayreg "github.com/boanlab/outrelay-relay/pkg/registry"
)

// Version is stamped at link time via -ldflags '-X main.Version=...'.
var Version = "dev"

func main() {
	var (
		listen          = flag.String("listen", "127.0.0.1:7443", "QUIC listen address")
		listenTCP       = flag.String("listen-tcp", "", "optional TCP+TLS+yamux listen address (e.g. 0.0.0.0:443) for the UDP-blocked fallback path. Empty disables.")
		listenForward   = flag.String("listen-forward", "", "optional UDP listen address (e.g. 0.0.0.0:9443) for the mini-TURN data plane (relay_mode=FORWARD). Agents in forward mode send packets here with the peer allocation id as a 4-byte prefix; the relay strips the prefix and forwards. Empty disables forward mode.")
		certPath        = flag.String("cert", "", "PEM-encoded server cert")
		keyPath         = flag.String("key", "", "PEM-encoded server key")
		caPath          = flag.String("ca", "", "PEM-encoded CA bundle for client cert verification")
		controllerAddr  = flag.String("controller", "127.0.0.1:7444", "controller gRPC address")
		controllerTLS   = flag.Bool("controller-tls", false, "dial the controller over mTLS using this relay's --cert/--key/--ca (default: insecure plaintext for backward compat with dev setups). Set when the controller was started with -cert/-key/-ca.")
		relayID         = flag.String("relay-id", "", "this relay's id (advertised via UpsertRelay; defaults to listen addr)")
		region          = flag.String("region", "local", "this relay's region label")
		advertised      = flag.String("advertise", "", "endpoint advertised to agents (defaults to --listen)")
		heartbeat       = flag.Duration("heartbeat", relayreg.DefaultHeartbeatPeriod, "how often to re-register with the controller and refresh the successor relay list handed to agents")
		drainOnSignal   = flag.Bool("drain-on-signal", true, "on SIGTERM/SIGINT send GOAWAY to every agent and wait up to --drain-timeout for them to relocate before exiting; a second signal exits immediately")
		drainTo         = flag.String("drain-to", "", "comma-separated relay endpoints named in GOAWAY (default: the successor list learned from the controller)")
		drainTimeout    = flag.Duration("drain-timeout", 10*time.Second, "how long agents get to relocate after GOAWAY before their links are closed")
		policyTenant    = flag.String("tenant", "", "tenant whose policies to subscribe to (empty = no policy enforcement)")
		debugListen     = flag.String("debug-listen", "127.0.0.1:9100", "localhost-only debug HTTP (/debug/metrics, /debug/pprof). Empty disables.")
		metricsDump     = flag.String("metrics-dump", "", "JSONL file path for periodic metrics dump (empty disables)")
		metricsInterval = flag.Duration("metrics-interval", 10*time.Second, "metrics dump interval")
		logFormat       = flag.String("log-format", "text", "log format: text or json")
		logLevel        = flag.String("log-level", "info", "log level: debug, info, warn, error")
		showVersion     = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(Version)
		return
	}

	logger := newLogger(*logFormat, *logLevel)
	if *certPath == "" || *keyPath == "" || *caPath == "" {
		logger.Error("missing required flags", "cert", *certPath, "key", *keyPath, "ca", *caPath)
		os.Exit(2)
	}

	tlsConf, err := loadServerTLS(*certPath, *keyPath, *caPath)
	if err != nil {
		logger.Error("load tls", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)

	ctrlCreds, err := controllerCreds(*controllerTLS, tlsConf)
	if err != nil {
		logger.Error("relay: build controller creds", "err", err)
		os.Exit(1)
	}
	if *controllerTLS {
		logger.Info("relay: controller gRPC over mTLS", "addr", *controllerAddr)
	} else {
		logger.Warn("relay: controller gRPC plaintext — pair with controller-side -cert/-key/-ca and set -controller-tls for production",
			"addr", *controllerAddr)
	}
	cc, err := grpc.NewClient(*controllerAddr,
		grpc.WithTransportCredentials(ctrlCreds),
	)
	if err != nil {
		logger.Error("dial controller", "addr", *controllerAddr, "err", err)
		os.Exit(1)
	}
	defer cc.Close()
	ctrl := pb.NewRegistryClient(cc)

	id := *relayID
	if id == "" {
		id = *listen
	}
	advert := *advertised
	if advert == "" {
		advert = *listen
	}

	upsertCtx, upsertCancel := context.WithTimeout(ctx, 5*time.Second)
	first, err := ctrl.UpsertRelay(upsertCtx, &pb.UpsertRelayRequest{
		Id: id, Region: *region, Endpoint: advert,
	})
	upsertCancel()
	if err != nil {
		logger.Error("upsert relay", "err", err)
		os.Exit(1)
	}
	logger.Info("relay self-registered", "id", id, "controller", *controllerAddr,
		"version", Version, "fleet", len(first.Relays))

	reg := relayreg.New(ctrl, id, *region, logger)

	var (
		policyEngine *policy.Engine
		policyCache  *policy.Cache
		auditEm      *audit.Emitter
	)
	if *policyTenant != "" {
		policyEngine = policy.NewEngine()
		policyCache = policy.NewCache()
		auditEm = audit.NewEmitter(pb.NewAuditClient(cc), logger)
		watcher := policy.NewWatcher(pb.NewPolicyClient(cc), *policyTenant, policyEngine, policyCache, logger)
		go func() { _ = watcher.Run(ctx) }()
		go func() { _ = auditEm.Run(ctx) }()
		logger.Info("policy enforcement enabled", "tenant", *policyTenant)
	}

	// Inter-relay forwarding pool. The relay reuses its own server
	// cert as a client cert when dialing peer relays — both sides see
	// the URI SAN and verify against the shared CA.
	pool := intra.NewPool(intraTLS(tlsConf), logger)
	defer func() { _ = pool.Close() }()

	// Observability — shared registry, optional debug HTTP and JSONL dump.
	obsReg := observe.NewRegistry()
	if *metricsDump != "" {
		go func() {
			if err := observe.NewDumper(obsReg, *metricsDump, *metricsInterval).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("metrics dumper", "err", err)
			}
		}()
	}

	// Optional mini-TURN forwarding plane (relay_mode=FORWARD).
	// Independent UDP socket from the QUIC listener — the relay
	// does not terminate QUIC for these flows; it just rewrites
	// the prefix and forwards the payload to the registered peer.
	// Constructed before edge.New so the Server can carry the
	// plane reference and dispatch to it from handleConsumerStream
	// when policy says forward.
	var forwardPlane *forward.Plane
	if *listenForward != "" {
		fp, err := forward.NewPlane(*listenForward, logger)
		if err != nil {
			logger.Error("listen-forward", "addr", *listenForward, "err", err)
			os.Exit(1)
		}
		forwardPlane = fp
		go func() {
			logger.Info("relay listening (mini-TURN forward plane)", "addr", fp.Endpoint().String())
			if err := fp.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("listen-forward loop exited", "err", err)
			}
		}()
	} else {
		logger.Warn("forward plane disabled (--listen-forward empty) — relay_mode=forward policies will silently downgrade to splice on this relay")
	}

	srv := edge.New(*listen, tlsConf, reg, policyEngine, policyCache, auditEm, pool, forwardPlane, obsReg, logger)

	// Successor list: seeded from the startup snapshot, then refreshed
	// by the heartbeat so agents always hold a current fallback list
	// (HELLO_ACK.successor_endpoints / per-stream resume_relays).
	srv.SetSuccessors(relayreg.Successors(id, *region, first.Relays))
	hb := relayreg.NewHeartbeat(ctrl, id, *region, advert, *heartbeat, logger)
	hb.OnSuccessors(srv.SetSuccessors)
	go hb.Run(ctx)

	// Planned relocation (GOAWAY) — two operator entry points sharing
	// the same defaults: SIGTERM (k8s pod termination, rolling
	// upgrade) and POST /debug/drain on the localhost debug port
	// (manual rebalance / preempt).
	drainDefaults := edge.DrainDefaults{
		Targets:  splitEndpoints(*drainTo),
		Reason:   "drain",
		Deadline: *drainTimeout,
	}
	if *debugListen != "" {
		mux := http.NewServeMux()
		mux.Handle("/", observe.DebugMux(obsReg))
		mux.Handle("/debug/drain", edge.DrainHandler(drainDefaults,
			func(targets []string, reason string, deadline time.Duration) {
				go srv.Drain(ctx, targets, reason, deadline)
			}, logger))
		go func() {
			if err := observe.ServeDebugHandler(ctx, *debugListen, mux); err != nil {
				logger.Warn("debug http", "err", err)
			}
		}()
	}
	go func() {
		<-sigC
		if !*drainOnSignal {
			cancel()
			return
		}
		logger.Info("signal received; draining agents before exit",
			"targets", drainDefaults.Targets, "timeout", drainDefaults.Deadline)
		done := make(chan struct{})
		go func() {
			srv.Drain(ctx, drainDefaults.Targets, drainDefaults.Reason, drainDefaults.Deadline)
			close(done)
		}()
		select {
		case <-done:
		case <-sigC:
			logger.Warn("second signal; exiting without waiting for drain")
		}
		cancel()
	}()

	// Optional TCP+TLS fallback listener for environments that block
	// UDP. Same Server, same handlers — yamux multiplexes streams
	// over the TCP connection so each accepted Conn satisfies the
	// existing transport.Conn interface and plugs straight into
	// Server.RunListener.
	if *listenTCP != "" {
		ln, err := transport.ListenTCP(*listenTCP, tlsConf)
		if err != nil {
			logger.Error("listen-tcp", "addr", *listenTCP, "err", err)
			os.Exit(1)
		}
		go func() {
			logger.Info("relay listening (tcp+tls fallback)", "addr", ln.Addr())
			if err := srv.RunListener(ctx, ln); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("listen-tcp loop exited", "err", err)
			}
		}()
	}

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("relay exited", "err", err)
		os.Exit(1)
	}
}

// controllerCreds picks the gRPC transport credentials for the
// controller dial. When mTLS is requested it derives a client config
// from the relay's existing serverConf — same cert (which carries
// this relay's URI SAN, satisfying the controller's
// RequireAndVerifyClientCert) and same trust pool. When mTLS is
// disabled it returns plaintext credentials so dev setups continue
// to work without controller-side -cert/-key/-ca.
//
// ServerName defaults to "localhost" matching dev-pki's DNS SAN —
// production should override (e.g., via cert with a controller URI
// SAN) but this baseline keeps the in-tree e2e harnesses working.
func controllerCreds(enableTLS bool, serverConf *tls.Config) (credentials.TransportCredentials, error) {
	if !enableTLS {
		return insecure.NewCredentials(), nil
	}
	if serverConf == nil {
		return nil, fmt.Errorf("relay: -controller-tls requires -cert/-key/-ca to be set")
	}
	c := serverConf.Clone()
	c.ClientCAs = nil
	c.ClientAuth = 0
	c.RootCAs = serverConf.ClientCAs
	c.ServerName = "localhost"
	return credentials.NewTLS(c), nil
}

// intraTLS builds a client tls.Config from the relay's server config —
// same cert (which carries the relay's URI SAN), same CA pool. Used
// as the dial config for inter-relay connections.
//
// ServerName stays "localhost" so dev-pki's DNS-SAN cert chain still
// verifies, but a VerifyConnection callback additionally enforces that
// the peer's leaf cert carries a relay-role URI SAN
// (`outrelay://<tenant>/relay/<id>`). Without that check the
// inter-relay dial would accept any agent's leaf cert as a peer relay,
// since both kinds chain to the same CA in a typical deployment.
func intraTLS(serverConf *tls.Config) *tls.Config {
	c := serverConf.Clone()
	c.ClientCAs = nil
	c.ClientAuth = 0
	c.RootCAs = serverConf.ClientCAs
	c.ServerName = "localhost"
	c.VerifyConnection = verifyPeerIsRelay
	return c
}

// verifyPeerIsRelay checks that the peer's verified leaf cert carries
// at least one URI SAN of the form outrelay://<tenant>/relay/<id>.
// Runs after Go's default chain verification so the cert is already
// known to be CA-signed; this only rejects agent-role certs from
// being accepted as peer relays.
func verifyPeerIsRelay(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return fmt.Errorf("intra: peer presented no verified chain")
	}
	leaf := cs.VerifiedChains[0][0]
	for _, u := range leaf.URIs {
		if u == nil {
			continue
		}
		// Scheme + path shape: outrelay://<tenant>/relay/<id>.
		// We intentionally accept any tenant — the trust domain is
		// already constrained by the CA pool; further per-tenant
		// scoping is a controller-side concern.
		if u.Scheme == "outrelay" && len(u.Path) > len("/relay/") &&
			u.Path[:len("/relay/")] == "/relay/" {
			return nil
		}
	}
	return fmt.Errorf("intra: peer leaf has no relay URI SAN (got %v)", leaf.URIs)
}

func loadServerTLS(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	// caPath comes from a flag wired by the operator, by design.
	caPEM, err := os.ReadFile(caPath) // #nosec G304
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("tls: empty ca PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func newLogger(format, level string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLogLevel(level)}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// splitEndpoints parses a comma-separated host:port list, dropping
// empty items. Empty input yields nil (= "use advertised successors").
func splitEndpoints(raw string) []string {
	var out []string
	for _, ep := range strings.Split(raw, ",") {
		if ep = strings.TrimSpace(ep); ep != "" {
			out = append(out, ep)
		}
	}
	return out
}
