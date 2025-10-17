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
	IssuerURL       string          `yaml:"issuerURL"`
	Audience        string          `yaml:"audience"`
	Allowed         []AllowedCaller `yaml:"allowed"`
}

// ServiceRegistrationFunc is a callback function to register services on the gRPC server
type ServiceRegistrationFunc func(*grpc.Server) error

type Server struct {
	config       *ServerConfig
	log          *zerolog.Logger
	listener     net.Listener
	GrpcServer   *grpc.Server
	verifier     *oidc.IDTokenVerifier
	httpClient   *http.Client
	podNamespace string
	certWatcher  *config.Watcher
	serverMu     sync.RWMutex
	reloadMu     sync.Mutex
	isRunning    bool

	// Service registration callbacks
	serviceRegistrationMu sync.RWMutex
	serviceRegistrations  []ServiceRegistrationFunc
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

func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.IssuerURL == "" {
		cfg.IssuerURL = "https://kubernetes.default.svc.cluster.local"
	}
	if cfg.CertReloadDelay == 0 {
		cfg.CertReloadDelay = 2 * time.Second
	}

	s := &Server{
		config:               cfg,
		log:                  logger.NewLogger("grpc"),
		serviceRegistrations: make([]ServiceRegistrationFunc, 0),
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

	if err := s.initOIDC(); err != nil {
		return nil, fmt.Errorf("init oidc: %w", err)
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

// RegisterService adds a service registration callback that will be called
// whenever the gRPC server is created or recreated (e.g., after certificate reload)
func (s *Server) RegisterService(regFunc ServiceRegistrationFunc) error {
	s.serviceRegistrationMu.Lock()
	defer s.serviceRegistrationMu.Unlock()

	s.serviceRegistrations = append(s.serviceRegistrations, regFunc)

	s.serverMu.RLock()
	currentServer := s.GrpcServer
	s.serverMu.RUnlock()

	if currentServer != nil {
		if err := regFunc(currentServer); err != nil {
			return fmt.Errorf("failed to register service: %w", err)
		}
		s.log.Debug().Msg("Service registered successfully")
	}

	return nil
}

// registerAllServices calls all registered service registration functions
func (s *Server) registerAllServices() error {
	s.serviceRegistrationMu.RLock()
	defer s.serviceRegistrationMu.RUnlock()

	s.serverMu.RLock()
	currentServer := s.GrpcServer
	s.serverMu.RUnlock()

	if currentServer == nil {
		return fmt.Errorf("no gRPC server available")
	}

	for i, regFunc := range s.serviceRegistrations {
		if err := regFunc(currentServer); err != nil {
			return fmt.Errorf("failed to register service %d: %w", i, err)
		}
	}

	s.log.Debug().Int("count", len(s.serviceRegistrations)).Msg("All services registered successfully")
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

	opts = append(opts, grpc.ChainUnaryInterceptor(
		s.unaryRequestLoggingInterceptor(),
		s.unaryAuthInterceptor(),
		s.unaryErrorLoggingInterceptor(),
	))

	s.serverMu.Lock()
	s.GrpcServer = grpc.NewServer(opts...)
	s.serverMu.Unlock()

	// Register all services on the new server
	if err := s.registerAllServices(); err != nil {
		return fmt.Errorf("failed to register services: %w", err)
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

	s.serverMu.Lock()
	oldServer := s.GrpcServer
	s.serverMu.Unlock()

	if err := s.initGRPCServer(); err != nil {
		s.log.Error().Err(err).Msg("Failed to create new gRPC server")
		return fmt.Errorf("failed to create new gRPC server: %w", err)
	}

	if oldServer != nil {
		s.log.Debug().Msg("Gracefully stopping old gRPC server")
		oldServer.GracefulStop()
	}

	s.log.Info().Msg("Successfully reloaded TLS certificates and re-registered services")
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
	s.serverMu.Lock()
	s.isRunning = true
	s.serverMu.Unlock()

	s.log.Info().
		Str("address", s.listener.Addr().String()).
		Bool("tls", s.config.EnableTLS).
		Msg("Starting gRPC server")

	for {
		s.serverMu.RLock()
		server := s.GrpcServer
		running := s.isRunning
		s.serverMu.RUnlock()

		if !running {
			break
		}

		if err := server.Serve(s.listener); err != nil {
			s.log.Error().Err(err).Msg("gRPC server error")

			s.serverMu.RLock()
			stillRunning := s.isRunning
			s.serverMu.RUnlock()

			if !stillRunning {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil
}

func (s *Server) Stop() {
	s.log.Info().Msg("Stopping gRPC server")

	s.serverMu.Lock()
	s.isRunning = false
	if s.GrpcServer != nil {
		s.GrpcServer.GracefulStop()
	}
	s.serverMu.Unlock()

	if s.certWatcher != nil {
		if err := s.certWatcher.Close(); err != nil {
			s.log.Error().Err(err).Msg("Error closing certificate watcher")
		}
	}

	if s.listener != nil {
		s.listener.Close()
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

		logEvent := s.log.Info().
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

		if err != nil {
			logEvent = logEvent.Err(err)
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

// UnaryErrorLoggingInterceptor logs all gRPC errors returned by handlers.
func (s *Server) unaryErrorLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		resp, err = handler(ctx, req)
		if err != nil {
			st := status.Convert(err)
			s.log.Error().
				Str("method", info.FullMethod).
				Str("code", st.Code().String()).
				Err(err).
				Msg("gRPC error occurred")
		}
		return resp, err
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
