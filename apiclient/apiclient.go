package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/k8shell-io/common/logger"
	"github.com/rs/zerolog"
)

// Config represents the configuration for the API client.
type Config struct {
	BaseURL             string      `yaml:"baseURL"`
	APIKey              string      `yaml:"APIKey"`
	Timeout             int         `yaml:"timeout"`
	MaxIdleConns        int         `yaml:"maxIdleConns"`
	MaxIdleConnsPerHost int         `yaml:"maxIdleConnsPerHost"`
	IdleConnTimeout     int         `yaml:"idleConnTimeout"`
	DialTimeout         int         `yaml:"dialTimeout"`
	KeepAlive           int         `yaml:"keepAlive"`
	TLSHandshakeTimeout int         `yaml:"tlsHandshakeTimeout"`
	Retry               RetryConfig `yaml:"retry"`
}

// RetryConfig represents retry configuration
type RetryConfig struct {
	MaxRetries    int           `yaml:"maxRetries"`
	InitialDelay  time.Duration `yaml:"initialDelay"`
	MaxDelay      time.Duration `yaml:"maxDelay"`
	BackoffFactor float64       `yaml:"backoffFactor"`
}

// setDefaults sets default values for Config fields that are zero
func (c *Config) setDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 30
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = 20
	}
	if c.MaxIdleConnsPerHost == 0 {
		c.MaxIdleConnsPerHost = 10
	}
	if c.IdleConnTimeout == 0 {
		c.IdleConnTimeout = 90
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 5
	}
	if c.KeepAlive == 0 {
		c.KeepAlive = 30
	}
	if c.TLSHandshakeTimeout == 0 {
		c.TLSHandshakeTimeout = 5
	}
	if c.Retry.InitialDelay == 0 {
		c.Retry.InitialDelay = 100 * time.Millisecond
	}
	if c.Retry.MaxDelay == 0 {
		c.Retry.MaxDelay = 2 * time.Second
	}
	if c.Retry.BackoffFactor == 0 {
		c.Retry.BackoffFactor = 2.0
	}
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// APIError represents an error returned by the API
type APIError struct {
	StatusCode int
	Message    string
}

// Error implements the error interface for APIError
func (e *APIError) Error() string {
	return e.Message
}

// Client represents the provisioner API client
type Client struct {
	baseURL     string
	apiKey      string
	httpClient  *http.Client
	log         *zerolog.Logger
	retryConfig RetryConfig
}

// NewClient creates a new provisioner API client
func NewClient(config Config, logName string) *Client {
	config.setDefaults()

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.DialTimeout) * time.Millisecond,
			KeepAlive: time.Duration(config.KeepAlive) * time.Millisecond,
		}).DialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     time.Duration(config.IdleConnTimeout) * time.Millisecond,
		TLSHandshakeTimeout: time.Duration(config.TLSHandshakeTimeout) * time.Millisecond,
		DisableKeepAlives:   false,
	}

	return &Client{
		baseURL: config.BaseURL,
		apiKey:  config.APIKey,
		httpClient: &http.Client{
			Timeout:   time.Duration(config.Timeout) * time.Millisecond,
			Transport: transport,
		},
		log:         logger.NewLogger(logName),
		retryConfig: config.Retry,
	}
}

// ForwardHandler returns a handler function that forwards the request to the target URL
func (c *Client) ForwardHandler(srcPath, dstPath string) gin.HandlerFunc {
	return func(cg *gin.Context) {
		localDstPath := dstPath

		srcParams := extractParamsFromRoute(srcPath)
		for _, param := range srcParams {
			value, exists := cg.Get(param)
			var paramValue string

			if exists {
				if str, ok := value.(string); ok {
					paramValue = str
				} else {
					c.log.Error().Str("param", param).Msg("URL parameter is not a string")
					cg.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError,
						"msg": "Internal server error"})
					return
				}
			} else {
				paramValue = cg.Param(param)
			}

			if paramValue == "" {
				c.log.Error().Str("param", param).Msg("Missing URL parameter")
				cg.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest,
					"msg": fmt.Sprintf("Missing URL parameter: %s", param)})
				return
			}
			localDstPath = strings.ReplaceAll(localDstPath, ":"+param, paramValue)
		}

		c.log.Debug().Str("origPath", cg.Request.URL.Path).Str("newURL", localDstPath).Msg("Forwarding request")
		c.doForward(cg, localDstPath)
	}
}

// ForwardRequest forwards a HTTP request to the provisioner API
func (c *Client) doForward(cg *gin.Context, url string) {
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

// MakeRequestWithRetry implements retry logic
func (c *Client) MakeRequestWithRetry(ctx context.Context, method, endpoint string, body io.Reader,
	contentType string) (*http.Response, error) {
	var lastErr error
	delay := c.retryConfig.InitialDelay

	for attempt := 0; attempt <= c.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			c.log.Warn().Msgf("Retrying request to %s (attempt %d/%d)", endpoint, attempt, c.retryConfig.MaxRetries)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			delay = time.Duration(float64(delay) * c.retryConfig.BackoffFactor)
			if delay > c.retryConfig.MaxDelay {
				delay = c.retryConfig.MaxDelay
			}
		}

		var bodyReader io.Reader
		if body != nil {
			if seeker, ok := body.(io.Seeker); ok {
				seeker.Seek(0, 0)
				bodyReader = body
			} else if bodyBytes, ok := body.(*strings.Reader); ok {
				bodyBytes.Seek(0, 0)
				bodyReader = bodyBytes
			} else {
				if attempt > 0 {
					return nil, fmt.Errorf("cannot retry request with non-seekable body")
				}
				bodyReader = body
			}
		}

		resp, err := c.makeRequest(ctx, method, endpoint, bodyReader, contentType)
		if err == nil {
			if !c.isRetryableStatusCode(resp.StatusCode) {
				return resp, nil
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("received non-retryable status code: %d", resp.StatusCode)
		} else if !c.isRetryableError(err) {
			return nil, err
		} else {
			lastErr = err
		}

		c.log.Warn().Msgf("Request failed: %v", lastErr)
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.retryConfig.MaxRetries, lastErr)
}

// makeRequest makes a single HTTP request without retries
func (c *Client) makeRequest(ctx context.Context, method, endpoint string, body io.Reader,
	contentType string) (*http.Response, error) {
	url := c.baseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "k8shell-api-client/1.0")

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

// isRetryableError determines if an error should trigger a retry
func (c *Client) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}

	errStr := err.Error()
	retryableErrors := []string{
		"connection refused",
		"connection reset",
		"i/o timeout",
		"no such host",
		"network is unreachable",
		"connection timed out",
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(strings.ToLower(errStr), retryableErr) {
			return true
		}
	}

	return false
}

// isRetryableStatusCode determines if an HTTP status code should trigger a retry
func (c *Client) isRetryableStatusCode(statusCode int) bool {
	switch statusCode {
	case 429, // Too Many Requests
		500, // Internal Server Error
		502, // Bad Gateway
		503, // Service Unavailable
		504: // Gateway Timeout
		return true
	default:
		return false
	}
}

// MakeRequest makes an HTTP request to the API with retry functionality
func (c *Client) MakeRequest(ctx context.Context, method, endpoint string, body io.Reader,
	contentType string) (*http.Response, error) {
	if c.retryConfig.MaxRetries > 0 {
		return c.MakeRequestWithRetry(ctx, method, endpoint, body, contentType)
	} else {
		return c.makeRequest(ctx, method, endpoint, body, contentType)
	}
}

func (c *Client) CheckError(resp *http.Response) error {
	if resp.StatusCode >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return &APIError{StatusCode: resp.StatusCode, Message: "failed to decode error response"}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: errResp.Error}
	}
	return nil
}

// handleResponse handles API response and error parsing, returns body content
func (c *Client) HandleResponse(resp *http.Response, v interface{}) (string, error) {
	defer resp.Body.Close()

	err := c.CheckError(resp)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	bodyString := string(body)

	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			return bodyString, fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return bodyString, nil
}

// extractParamsFromRoute extracts parameter names from a route pattern like "/users/:username/sessions"
func extractParamsFromRoute(route string) []string {
	var params []string
	parts := strings.Split(route, "/")

	for _, part := range parts {
		if strings.HasPrefix(part, ":") {
			paramName := strings.TrimPrefix(part, ":")
			if paramName != "" {
				params = append(params, paramName)
			}
		}
	}

	return params
}
