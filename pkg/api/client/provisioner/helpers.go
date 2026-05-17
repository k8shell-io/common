package provisioner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	provisionerv1 "github.com/k8shell-io/common/pkg/api/gen/go/provisioner/v1"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/userstr"
	"google.golang.org/grpc"
)

var ErrWorkspaceExists = errors.New("workspace already exists")
var ErrInvalidArgument = errors.New("invalid argument")

type Client struct {
	provisionerv1.ProvisionerServiceClient
	client *gapi.Client
}

func NewClient(cfg gapi.ClientConfig) (*Client, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		ProvisionerServiceClient: provisionerv1.NewProvisionerServiceClient(gapiClient.Conn),
		client:                   gapiClient,
	}, nil
}

func (c *Client) Close() error {
	return c.client.Close()
}

// ProvisionHandshake reads the first stream event that needs to be handshake.
func (c *Client) ProvisionHandshake(ctx context.Context, us userstr.UserStr, timeout int32) (workspaceName string, jobID string, stream grpc.ServerStreamingClient[provisionerv1.ProvisionWorkspaceResponse], err error) {
	stream, err = c.ProvisionWorkspaceStream(ctx, &provisionerv1.ProvisionWorkspaceRequest{
		Userstr:      us.Raw(),
		SendProgress: true,
		SendEvents:   true,
		Timeout:      timeout,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to start provisioning stream: %w", err)
	}
	return c.waitForHandshakeMessage(stream)
}

func (c *Client) waitForHandshakeMessage(
	stream grpc.ServerStreamingClient[provisionerv1.ProvisionWorkspaceResponse],
) (string, string, grpc.ServerStreamingClient[provisionerv1.ProvisionWorkspaceResponse], error) {
	first, err := stream.Recv()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to receive first stream event (handshake expected): %w", err)
	}

	hs := first.GetHandshake()
	if hs == nil {
		return "", "", nil, fmt.Errorf("invalid first stream event: expected handshake, got %+v", first)
	}

	if hs.GetError() != "" {
		code, desc := extractErrorCodeAndDesc(hs.GetError())
		if code == "AlreadyExists" || code == "PreconditionFailed" {
			return "", "", nil, fmt.Errorf("%w: handshake failed: %w", ErrWorkspaceExists, errors.New(desc))
		}
		if code == "InvalidArgument" {
			return "", "", nil, fmt.Errorf("%w: handshake failed: %w", ErrInvalidArgument, errors.New(desc))
		}
		if code == "FailedPrecondition" {
			return "", "", nil, fmt.Errorf("%w: handshake failed: %w", ErrWorkspaceExists, errors.New(desc))
		}
		return "", "", nil, fmt.Errorf("handshake failed: %w", errors.New(desc))
	}

	workspaceName := hs.GetWorkspace()
	jobID := hs.GetJobid()
	if workspaceName == "" {
		workspaceName = "n/a"
	}

	return workspaceName, jobID, stream, nil
}

func extractErrorCodeAndDesc(s string) (code string, desc string) {
	s = strings.TrimSpace(s)

	const descKey = "desc = "
	if i := strings.LastIndex(s, descKey); i >= 0 {
		desc = strings.TrimSpace(s[i+len(descKey):])
		desc = strings.Trim(desc, `"`)
	}

	const codeKey = "code = "
	if i := strings.LastIndex(s, codeKey); i >= 0 {
		rest := strings.TrimSpace(s[i+len(codeKey):])
		if j := strings.IndexAny(rest, " \t\r\n"); j >= 0 {
			code = strings.TrimSpace(rest[:j])
		} else {
			code = rest
		}
		code = strings.Trim(code, `"`)
	}

	return code, desc
}
