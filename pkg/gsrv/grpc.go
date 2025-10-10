package gsrv

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Config struct {
	Port      int    `yaml:"port"`
	enableTLS bool   `yaml:"enableTLS"`
	certFile  string `yaml:"certFile"`
	keyFile   string `yaml:"keyFile"`
}

type Server struct {
	Config     *Config
	listener   net.Listener
	grpcServer *grpc.Server
}

// Start starts the gRPC server with optional TLS
func NewServer(config *Config) (*Server, error) {
	server := &Server{
		Config: config,
	}

	var err error
	server.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	if config.enableTLS {
		creds, err := credentials.NewServerTLSFromFile(config.certFile, config.keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		server.grpcServer = grpc.NewServer(grpc.Creds(creds))
	} else {
		server.grpcServer = grpc.NewServer()
	}

	return server, nil
}
