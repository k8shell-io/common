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
	"github.com/k8shell-io/common/logger"
	"github.com/rs/zerolog"
)

// Config represents the client configuration
type Config struct {
	BaseURL string `yaml:"baseURL"`
	APIKey  string `yaml:"APIKey"`
	Timeout int    `yaml:"timeout"`
}

type ClientInterface interface {
	ForwardHandler(srcPath, dstPath string) gin.HandlerFunc
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
	log        *zerolog.Logger
}

// NewClient creates a new provisioner API client
func NewClient(config Config, logName string) *Client {
	if config.Timeout == 0 {
		config.Timeout = 5
	}

	return &Client{
		baseURL: strings.TrimSuffix(config.BaseURL, "/"),
		apiKey:  config.APIKey,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
		log: logger.NewLogger(logName),
	}
}

// ForwardHandler returns a handler function that forwards the request to the target URL
func (c *Client) ForwardHandler(srcPath, dstPath string) gin.HandlerFunc {
	return func(cg *gin.Context) {
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
			dstPath = strings.ReplaceAll(dstPath, ":"+param, paramValue)
		}

		c.log.Debug().Str("origPath", cg.Request.URL.Path).Str("newURL", dstPath).Msg("Forwarding request")
		c.doForward(cg, dstPath)
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

// MakeRequest makes an HTTP request to the API
func (c *Client) MakeRequest(ctx context.Context, method, endpoint string, body io.Reader,
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
