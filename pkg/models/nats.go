package models

// FailedConnectionEvent represents a failed SSH connection attempt
type FailedConnectionEvent struct {
	ClientIP    string   `json:"client_ip"`
	ClientPort  int      `json:"client_port"`
	Username    string   `json:"username"`
	Timestamp   string   `json:"timestamp"`
	FailureInfo []string `json:"failure_info"`
	ProxyID     string   `json:"proxy_id"`
}
