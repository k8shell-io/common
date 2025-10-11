package gsrv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/k8shell-io/common/pkg/logger"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AllowedCaller struct {
	Namespace      string `yaml:"namespace"`
	ServiceAccount string `yaml:"serviceAccount"`
}

type Config struct {
	Port      int             `yaml:"port"`
	EnableTLS bool            `yaml:"enableTLS"`
	CertFile  string          `yaml:"certFile"`
	KeyFile   string          `yaml:"keyFile"`
	IssuerURL string          `yaml:"issuerURL"` // default "https://kubernetes.default.svc"
	Audience  string          `yaml:"audience"`  // must match "aud" claim in token
	Allowed   []AllowedCaller `yaml:"allowed"`   // list of allowed SA/ns
}

type Server struct {
	config     *Config
	log        *zerolog.Logger
	listener   net.Listener
	GrpcServer *grpc.Server

	verifier   *oidc.IDTokenVerifier
	httpClient *http.Client
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

func NewServer(cfg *Config) (*Server, error) {
	if cfg.IssuerURL == "" {
		cfg.IssuerURL = "https://kubernetes.default.svc.cluster.local"
	}
	s := &Server{config: cfg, log: logger.NewLogger("grpc")}

	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	caPEM, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read k8s ca: %w", err)
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
	jwksURL := strings.TrimRight(cfg.IssuerURL, "/") + "/openid/v1/jwks"
	ks := oidc.NewRemoteKeySet(oidcCtx, jwksURL)
	s.verifier = oidc.NewVerifier(cfg.IssuerURL, ks, &oidc.Config{ClientID: cfg.Audience})

	var opts []grpc.ServerOption
	if cfg.EnableTLS {
		creds, err := credentials.NewServerTLSFromFile(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls creds: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	opts = append(opts, grpc.ChainUnaryInterceptor(s.unaryAuthInterceptor(), s.unaryErrorLoggingInterceptor()))
	s.GrpcServer = grpc.NewServer(opts...)

	return s, nil
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

func (s *Server) Start() error {
	fmt.Printf("gRPC server listening on %s (tls=%v)\n", s.listener.Addr(), s.config.EnableTLS)
	if err := s.GrpcServer.Serve(s.listener); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func (s *Server) Stop() {
	s.GrpcServer.GracefulStop()
	s.listener.Close()
}

// *** Helpers

type callerKey struct{}
type Caller struct{ Namespace, ServiceAccount string }

func (s *Server) allowed(ns, sa string) bool {
	for _, a := range s.config.Allowed {
		if a.Namespace == ns && a.ServiceAccount == sa {
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
