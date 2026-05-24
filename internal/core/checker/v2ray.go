package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Import necessary components to register them
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

type Config interface {
	MarshalJSON() ([]byte, error)
}

type ConfigChecker interface {
	CheckConfig(config Config) (time.Duration, error)
}

type V2RayConfigChecker struct {
	timeout     time.Duration
	checkServer string
	checkPort   v2net.Port
}

func NewV2RayConfigChecker(timeout time.Duration, server string, port uint32) *V2RayConfigChecker {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if server == "" {
		server = "1.1.1.1"
	}
	if port == 0 {
		port = 80
	}
	return &V2RayConfigChecker{
		timeout:     timeout,
		checkServer: server,
		checkPort:   v2net.Port(port),
	}
}

type instanceConfig struct {
	Log       interface{}       `json:"log"`
	Inbounds  []json.RawMessage `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Routing   struct {
		Rules          []interface{} `json:"rules"`
		DomainStrategy string        `json:"domainStrategy"`
	} `json:"routing"`
	DNS struct {
		Servers []string `json:"servers"`
	} `json:"dns"`
}

func createInstanceConfig(outbound []byte) ([]byte, error) {
	config := instanceConfig{
		Log: map[string]interface{}{
			"loglevel": "none",
			"access":   "none",
			"error":    "none",
		},
		Inbounds: []json.RawMessage{
			json.RawMessage(`{
				"tag": "inbound-test",
				"listen": "127.0.0.1",
				"port": 0,
				"protocol": "socks",
				"settings": {
					"auth": "noauth",
					"udp": true,
					"timeout": 5
				},
				"sniffing": {
					"enabled": true,
					"destOverride": ["http", "tls"]
				}
			}`),
		},
		Outbounds: []json.RawMessage{outbound},
	}
	config.Routing.DomainStrategy = "IPIfNonMatch"
	config.DNS.Servers = []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"}

	return json.Marshal(config)
}

func (t *V2RayConfigChecker) CheckConfig(config Config) (time.Duration, error) {
	jsonConfig, err := config.MarshalJSON()
	if err != nil {
		return 0, fmt.Errorf("failed to marshal config: %w", err)
	}

	instanceConfig, err := createInstanceConfig(jsonConfig)
	if err != nil {
		return 0, fmt.Errorf("failed to create instance config: %w", err)
	}

	parsedConfig, err := serial.LoadJSONConfig(bytes.NewReader(instanceConfig))
	if err != nil {
		return 0, fmt.Errorf("failed to parse config: %w", err)
	}

	instance, err := core.New(parsedConfig)
	if err != nil {
		return 0, fmt.Errorf("failed to create Xray instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		return 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}
	defer instance.Close()

	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()

	dest := v2net.Destination{
		Network: v2net.Network_TCP,
		Address: v2net.ParseAddress(t.checkServer),
		Port:    t.checkPort,
	}

	start := time.Now()
	conn, err := core.Dial(ctx, instance, dest)
	if err != nil {
		return 0, fmt.Errorf("connection test failed: %w", err)
	}
	defer conn.Close()

	testData := []byte("ping")
	if _, err := conn.Write(testData); err != nil {
		return 0, fmt.Errorf("failed to write test data: %w", err)
	}

	buffer := make([]byte, 1024)
	if _, err := conn.Read(buffer); err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	return time.Since(start), nil
}
