package gapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/k8shell-io/common/pkg/config"
	"github.com/k8shell-io/common/pkg/logger"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type AllowedCaller struct {
	Namespace      string `yaml:"namespace"`
	ServiceAccount string `yaml:"serviceAccount"`
}

type ServerConfig struct {
	Port            int             `yaml:"port"`
	EnableTLS       bool            `yaml:"enableTLS"`
	CertFile        string          `yaml:"certFile"`
	KeyFile         string          `yaml:"keyFile"`
	CertReloadDelay time.Duration   `yaml:"certReloadDelay"`
	AuthEnabled     bool            `yaml:"authEnabled"`
	IssuerURL       string          `yaml:"issuerURL"`
	Audience        string          `yaml:"audience"`
	Allowed         []AllowedCaller `yaml:"allowed"`
}

// ServiceRegistrationFunc is a callback function to register services on the gRPC server
type ServiceRegistrationFunc func(*grpc.Server) error

type Server struct {
	config               *ServerConfig
	log                  *zerolog.Logger
	listener             net.Listener
	GrpcServer           *grpc.Server
	verifier             *oidc.IDTokenVerifier
	httpClient           *http.Client
	podNamespace         string
	certWatcher          *config.Watcher
	reloadMu             sync.Mutex
	isRunning            bool
	serviceRegistrations ServiceRegistrationFunc
	stopGracefully       bool
	customInterceptors   []grpc.UnaryServerInterceptor
}

type roundTripperWithAuth struct {
	base http.RoundTripper
	hdr  string
}

func (r roundTripperWithAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", r.hdr)
	return r.base.RoundTrip(req2)
}

func NewServer(cfg *ServerConfig, stopGracefully bool) (*Server, error) {
	if cfg.IssuerURL == "" {
		cfg.IssuerURL = "https://kubernetes.default.svc.cluster.local"
	}
	if cfg.CertReloadDelay == 0 {
		cfg.CertReloadDelay = 2 * time.Second
	}

	s := &Server{
		config:               cfg,
		log:                  logger.NewLogger("grpc"),
		serviceRegistrations: nil,
		stopGracefully:       stopGracefully,
		customInterceptors:   []grpc.UnaryServerInterceptor{},
	}

	var err error
	namespaceBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to read pod namespace, using 'default'")
		s.podNamespace = "default"
	} else {
		s.podNamespace = strings.TrimSpace(string(namespaceBytes))
	}

	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	if err := s.initGRPCServer(); err != nil {
		return nil, fmt.Errorf("init grpc server: %w", err)
	}

	if cfg.EnableTLS {
		if err := s.setupCertWatcher(); err != nil {
			return nil, fmt.Errorf("setup cert watcher: %w", err)
		}
	}

	return s, nil
}

func (s *Server) AddInterceptor(interceptor grpc.UnaryServerInterceptor) {
	s.customInterceptors = append(s.customInterceptors, interceptor)
}

// RegisterService adds a service registration callback
func (s *Server) RegisterService(regFunc ServiceRegistrationFunc) error {
	s.serviceRegistrations = regFunc

	s.reloadMu.Lock()
	currentServer := s.GrpcServer
	s.reloadMu.Unlock()

	if currentServer != nil {
		if err := regFunc(currentServer); err != nil {
			return fmt.Errorf("failed to register service: %w", err)
		}
		s.log.Debug().Msg("Service registered successfully")
	}

	return nil
}

func (s *Server) initOIDC() error {
	caPEM, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return fmt.Errorf("read k8s ca: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	token, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	authTransport := roundTripperWithAuth{
		base: base,
		hdr:  "Bearer " + strings.TrimSpace(string(token)),
	}

	s.httpClient = &http.Client{
		Transport: authTransport,
		Timeout:   10 * time.Second,
	}

	oidcCtx := oidc.ClientContext(context.Background(), s.httpClient)
	jwksURL := strings.TrimRight(s.config.IssuerURL, "/") + "/openid/v1/jwks"
	ks := oidc.NewRemoteKeySet(oidcCtx, jwksURL)
	s.verifier = oidc.NewVerifier(s.config.IssuerURL, ks, &oidc.Config{ClientID: s.config.Audience})

	return nil
}

func (s *Server) initGRPCServer() error {
	var opts []grpc.ServerOption

	if s.config.EnableTLS {
		creds, err := credentials.NewServerTLSFromFile(s.config.CertFile, s.config.KeyFile)
		if err != nil {
			return fmt.Errorf("tls creds: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	var unaryInts []grpc.UnaryServerInterceptor
	unaryInts = append(unaryInts, s.unaryRequestLoggingInterceptor())

	if s.config.AuthEnabled {
		if err := s.initOIDC(); err != nil {
			return fmt.Errorf("init oidc: %w", err)
		}
		unaryInts = append(unaryInts, s.unaryAuthInterceptor())
	} else {
		s.log.Warn().Msg("Auth disabled; skipping oidc initialization and auth interceptor")
	}

	unaryInts = append(unaryInts, s.customInterceptors...)
	opts = append(opts, grpc.ChainUnaryInterceptor(unaryInts...))

	s.GrpcServer = grpc.NewServer(opts...)

	if s.serviceRegistrations != nil {
		if err := s.serviceRegistrations(s.GrpcServer); err != nil {
			return fmt.Errorf("failed to register service: %w", err)
		}
	} else {
		s.log.Warn().Msg("No services registered on gRPC server")
	}

	return nil
}

func (s *Server) setupCertWatcher() error {
	certDir := filepath.Dir(s.config.CertFile)
	keyDir := filepath.Dir(s.config.KeyFile)

	watchDir := certDir

	// If certificates are in different directories, we need to watch the common parent
	// or the cert directory (most common case is they're in the same directory)
	if keyDir != certDir {
		if strings.HasPrefix(keyDir, certDir) {
			watchDir = certDir
		} else if strings.HasPrefix(certDir, keyDir) {
			watchDir = keyDir
		} else {
			watchDir = findCommonParent(certDir, keyDir)
		}
	}

	certExtensions := []string{".crt", ".cert", ".pem", ".key"}
	s.certWatcher = config.NewWatcher(watchDir, s.config.CertReloadDelay, certExtensions, s.reloadCertificates)

	if err := s.certWatcher.Setup(); err != nil {
		return fmt.Errorf("setup certificate watcher: %w", err)
	}

	s.log.Debug().Msgf("Watching dir: %s, CertDir: %s, KeyDir: %s, extensions: %v, reloadDelay: %v, certFile: %s, keyFile: %s", watchDir, certDir, keyDir, certExtensions, s.config.CertReloadDelay,
		s.config.CertFile, s.config.KeyFile)

	return nil
}

// findCommonParent returns the common parent directory of two paths.
func findCommonParent(path1, path2 string) string {
	path1 = filepath.Clean(path1)
	path2 = filepath.Clean(path2)

	parts1 := strings.Split(path1, string(filepath.Separator))
	parts2 := strings.Split(path2, string(filepath.Separator))

	var common []string
	minLen := len(parts1)
	if len(parts2) < minLen {
		minLen = len(parts2)
	}

	for i := 0; i < minLen; i++ {
		if parts1[i] == parts2[i] {
			common = append(common, parts1[i])
		} else {
			break
		}
	}

	if len(common) == 0 {
		return "/"
	}

	return strings.Join(common, string(filepath.Separator))
}

func (s *Server) reloadCertificates() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	s.log.Info().
		Str("certFile", s.config.CertFile).
		Str("keyFile", s.config.KeyFile).
		Msg("Reloading TLS certificates and recreating gRPC server")

	if err := s.validateCertificates(); err != nil {
		s.log.Error().Err(err).Msg("Certificate validation failed, skipping reload")
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	oldServer := s.GrpcServer
	s.GrpcServer = nil

	if oldServer != nil {
		s.log.Debug().Msg("Gracefully stopping old gRPC server")
		if s.stopGracefully {
			s.log.Debug().Msg("Waiting for ongoing RPCs to complete")
			oldServer.GracefulStop()
		} else {
			s.log.Debug().Msg("Forcibly stopping old gRPC server")
			oldServer.Stop()
		}
	}

	oldListener := s.listener
	s.listener = nil

	if oldListener != nil {
		s.log.Debug().Msg("Closing old listener")
		oldListener.Close()
		time.Sleep(50 * time.Millisecond)
	}

	s.log.Debug().Msg("Creating new listener")
	newListener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		return fmt.Errorf("failed to create new listener: %w", err)
	}

	s.listener = newListener

	if err := s.initGRPCServer(); err != nil {
		s.log.Error().Err(err).Msg("Failed to create new gRPC server")
		newListener.Close()
		return fmt.Errorf("failed to create new gRPC server: %w", err)
	}

	s.log.Info().Msgf("TLS certificates reloaded, address: %s", newListener.Addr().String())
	return nil
}

func (s *Server) validateCertificates() error {
	if _, err := os.Stat(s.config.CertFile); err != nil {
		return fmt.Errorf("cert file not found: %w", err)
	}

	if _, err := os.Stat(s.config.KeyFile); err != nil {
		return fmt.Errorf("key file not found: %w", err)
	}

	_, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("invalid certificate pair: %w", err)
	}

	s.log.Debug().Msgf("Certificates %s and %s are valid", s.config.CertFile, s.config.KeyFile)

	return nil
}

func (s *Server) Start() error {
	s.reloadMu.Lock()
	s.isRunning = true
	s.reloadMu.Unlock()

	s.log.Info().
		Str("address", s.listener.Addr().String()).
		Bool("tls", s.config.EnableTLS).
		Msg("Starting gRPC server")

	for {
		s.reloadMu.Lock()
		server := s.GrpcServer
		currentListener := s.listener
		running := s.isRunning
		s.reloadMu.Unlock()

		if !running {
			break
		}

		if server == nil || currentListener == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		err := server.Serve(currentListener)

		s.reloadMu.Lock()
		stillRunning := s.isRunning
		s.reloadMu.Unlock()

		if !stillRunning {
			break
		}

		if err != nil {
			s.log.Debug().Err(err).Msg("Server serve ended, checking if reload occurred")
		}

		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

func (s *Server) Stop() {
	s.log.Info().Msg("Stopping gRPC server")

	s.reloadMu.Lock()
	s.isRunning = false
	if s.GrpcServer != nil {
		if s.stopGracefully {
			s.log.Debug().Msg("Waiting for ongoing RPCs to complete")
			s.GrpcServer.GracefulStop()
		} else {
			s.log.Debug().Msg("Forcibly stopping old gRPC server")
			s.GrpcServer.Stop()
		}
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.reloadMu.Unlock()

	if s.certWatcher != nil {
		if err := s.certWatcher.Close(); err != nil {
			s.log.Error().Err(err).Msg("Error closing certificate watcher")
		}
	}

	s.log.Info().Msg("gRPC server stopped")
}

// unaryRequestLoggingInterceptor logs all gRPC requests with timing and client info
func (s *Server) unaryRequestLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		start := time.Now()

		clientIP := "unknown"
		if p, ok := peer.FromContext(ctx); ok {
			if addr := p.Addr; addr != nil {
				if tcpAddr, ok := addr.(*net.TCPAddr); ok {
					clientIP = tcpAddr.IP.String()
				} else {
					clientIP = addr.String()
				}
			}
		}

		var namespace, serviceAccount string
		if caller, ok := ctx.Value(callerKey{}).(Caller); ok {
			namespace = caller.Namespace
			serviceAccount = caller.ServiceAccount
		}

		resp, err = handler(ctx, req)

		duration := time.Since(start)
		statusCode := codes.OK
		if err != nil {
			statusCode = status.Code(err)
		}

		var logEvent *zerolog.Event
		if err != nil {
			logEvent = s.log.Error().Err(err)
		} else {
			logEvent = s.log.Info()
		}

		logEvent = logEvent.
			Str("component", "grpc").
			Dur("duration", duration).
			Str("ip", clientIP).
			Str("method", info.FullMethod).
			Str("status", statusCode.String()).
			Int("pid", os.Getpid())

		if namespace != "" && serviceAccount != "" {
			logEvent = logEvent.
				Str("namespace", namespace).
				Str("serviceAccount", serviceAccount)
		}

		logEvent.Msg("grpc request")

		return resp, err
	}
}

// unaryAuthInterceptor verifies JWT and authorizes SA/namespace.
func (s *Server) unaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		raw, err := bearerFromMD(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		oidcCtx := oidc.ClientContext(ctx, s.httpClient)
		idt, err := s.verifier.Verify(oidcCtx, raw)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token: "+err.Error())
		}

		var kc struct {
			Kubernetes struct {
				Namespace      string `json:"namespace"`
				ServiceAccount struct {
					Name string `json:"name"`
					UID  string `json:"uid"`
				} `json:"serviceaccount"`
			} `json:"kubernetes.io"`
		}
		_ = idt.Claims(&kc)
		ns := kc.Kubernetes.Namespace
		sa := kc.Kubernetes.ServiceAccount.Name
		if ns == "" || sa == "" {
			return nil, status.Error(codes.PermissionDenied, "missing kubernetes.io claims")
		}

		if !s.allowed(ns, sa) {
			return nil, status.Errorf(codes.PermissionDenied, "unauthorized SA %s/%s", ns, sa)
		}

		ctx = context.WithValue(ctx, callerKey{}, Caller{Namespace: ns, ServiceAccount: sa})
		return handler(ctx, req)
	}
}

// *** Helpers

type callerKey struct{}
type Caller struct{ Namespace, ServiceAccount string }

func (s *Server) allowed(ns, sa string) bool {
	for _, a := range s.config.Allowed {
		allowedNamespace := a.Namespace
		if allowedNamespace == "" {
			allowedNamespace = s.podNamespace
		}

		if (allowedNamespace == ns || allowedNamespace == "*") &&
			(a.ServiceAccount == sa || a.ServiceAccount == "*") {
			return true
		}
	}
	return false
}

// bearerFromMD extracts a bearer token from gRPC metadata.
func bearerFromMD(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing metadata")
	}

	authz := md.Get("authorization")
	if len(authz) == 0 {
		return "", errors.New("missing authorization")
	}

	h := authz[0]
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return "", errors.New("expected Bearer token")
	}
	return strings.TrimSpace(h[len("Bearer "):]), nil
}
