// Package worktrace is the gRPC client detectors use to talk to the worktrace
// controller.
package worktrace

import (
	worktracev1 "github.com/k8shell-io/common/pkg/api/gen/go/worktrace/v1"
	"github.com/k8shell-io/common/pkg/gapi"
)

// Client calls the worktrace controller.
type Client struct {
	worktracev1.WorktraceControllerServiceClient
	conn *gapi.Client
}

// NewClient dials the controller using the shared gRPC client configuration.
func NewClient(cfg gapi.ClientConfig) (*Client, error) {
	conn, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		WorktraceControllerServiceClient: worktracev1.NewWorktraceControllerServiceClient(conn.Conn),
		conn:                             conn,
	}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
