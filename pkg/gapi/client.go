package gapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// ClientConfig holds configuration for gRPC client
type ClientConfig struct {
	// Address of the gRPC server, e.g. "localhost:50051"
	Address string `yaml:"address"`

	// ServerName is optional TLS ServerName for hostname verification.
	// Required if CACertPath is set and cert SAN doesn't match address host.
	ServerName string `yaml:"serverName"`

	// TokenFilePath is path to file containing token for authentication.
	// The file is read on each request to support token rotation.
	TokenFilePath string `yaml:"tokenFilePath"`

	// CACertPath is optional path to CA cert for TLS.
	//  If empty, TLS is disabled and credentials are insecure.
	CACertPath string `yaml:"caCertPath"`

	// Enabled controls whether this client is enabled.
	// If false, attempts to create a client will return an error.
	Enabled bool `yaml:"enabled"`
}

// ErrNotEnabled is returned by NewClient when the client is explicitly disabled.
var ErrNotEnabled = errors.New("not enabled")

// Client gRPC client
type Client struct {
	cfg  ClientConfig
	Conn *grpc.ClientConn
}

// PerRPCCredentials implementation that calls a func to fetch token.
type bearerCreds struct {
	secureRequired bool
	getToken       func(context.Context) (string, error)
}

func (b bearerCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	tok, err := b.getToken(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + strings.TrimSpace(tok)}, nil
}

func (b bearerCreds) RequireTransportSecurity() bool {
	return b.secureRequired
}

// FileTokenSource: reads the token file each call (handles rotation).
func fileTokenSource(path string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return string(b), nil
	}
}

// NewClient creates and returns a new gRPC client connection.
func NewClient(cfg ClientConfig) (*Client, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("%w: grpc api client is not enabled for address %s", ErrNotEnabled, cfg.Address)
	}
	if cfg.Address == "" {
		return nil, errors.New("addr required")
	}
	getTok := fileTokenSource(cfg.TokenFilePath)
	secureRequired := (cfg.CACertPath != "")
	creds := bearerCreds{secureRequired: secureRequired, getToken: getTok}

	var dialOpt grpc.DialOption
	if cfg.CACertPath == "" {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		var pool *x509.CertPool
		if cfg.CACertPath != "" {
			pem, err := os.ReadFile(cfg.CACertPath)
			if err != nil {
				return nil, fmt.Errorf("read CA: %w", err)
			}
			pool = x509.NewCertPool()
			pool.AppendCertsFromPEM(pem)
		}
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			ServerName: cfg.ServerName, // must match cert SAN when set
		}
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	}

	cc, err := grpc.NewClient(
		cfg.Address,
		dialOpt,
		grpc.WithPerRPCCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(32<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	return &Client{cfg: cfg, Conn: cc}, nil
}

// Close the gRPC client connection.
func (c *Client) Close() error {
	return c.Conn.Close()
}

// WithMD returns a new context with the provided key-value pairs added to outgoing gRPC metadata.
func WithMD(ctx context.Context, kv ...string) context.Context {
	if len(kv)%2 != 0 {
		return ctx
	}
	md := metadata.Pairs(kv...)
	return metadata.NewOutgoingContext(ctx, md)
}
