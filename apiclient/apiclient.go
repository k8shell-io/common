package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Config represents the client configuration
type Config struct {
	BaseURL string `yaml:"baseURL"`
	APIKey  string `yaml:"APIKey"`
	Timeout int    `yaml:"timeout"`
}

type ClientInterface interface {
	ForwardRequest(cg *gin.Context, url string)
	MakeRequest(ctx context.Context, method, endpoint string, body io.Reader,
		contentType string) (*http.Response, error)
	HandleResponse(resp *http.Response, v interface{}) error
	HandleErrorResponse(resp *http.Response) error
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// Client represents the provisioner API client
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new provisioner API client
func NewClient(config Config) *Client {
	if config.Timeout == 0 {
		config.Timeout = 5
	}

	return &Client{
		baseURL: strings.TrimSuffix(config.BaseURL, "/"),
		apiKey:  config.APIKey,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}
}

// ForwardRequest forwards a HTTP request to the provisioner API
func (c *Client) ForwardRequest(cg *gin.Context, url string) {
	downstreamURL := c.baseURL + url

	req, err := http.NewRequest(cg.Request.Method, downstreamURL, cg.Request.Body)
	if err != nil {
		cg.JSON(http.StatusInternalServerError, gin.H{"msg": "Failed to create forward request"})
		cg.Abort()
		return
	}

	for k, v := range cg.Request.Header {
		if strings.ToLower(k) == "authorization" {
			continue
		}
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		cg.JSON(http.StatusBadGateway, gin.H{"msg": "Forward request failed"})
		cg.Abort()
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			cg.Writer.Header().Add(k, vv)
		}
	}
	cg.Status(resp.StatusCode)
	io.Copy(cg.Writer, resp.Body)
	cg.Abort()
}

// MakeRequest makes an HTTP request to the API
func (c *Client) MakeRequest(ctx context.Context, method, endpoint string, body io.Reader,
	contentType string) (*http.Response, error) {
	url := c.baseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "k8shell-provisioner-client/1.0")

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if method == "GET" || method == "DELETE" {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// handleResponse handles API response and error parsing
func (c *Client) HandleResponse(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
		}
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, errResp.Error)
	}

	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// HandleErrorResponse handles error responses from the API
func (c *Client) HandleErrorResponse(resp *http.Response) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("API error (status %d): failed to read error response: %w", resp.StatusCode, err)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return fmt.Errorf("API error (status %d): %s", resp.StatusCode, errResp.Error)
}
