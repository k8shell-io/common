package models

// FailedConnectionEvent represents a failed SSH connection attempt
type FailedConnectionEvent struct {
	ClientIP    string   `json:"clientIP"`
	ClientPort  int      `json:"clientPort"`
	Username    string   `json:"username"`
	Timestamp   string   `json:"timestamp"`
	FailureInfo []string `json:"failureInfo"`
	ProxyID     string   `json:"proxyID"`
}
