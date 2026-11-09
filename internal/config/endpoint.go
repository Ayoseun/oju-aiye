package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// EndpointInfo describes where a model endpoint lives, so the platform can tell the operator
// whether their code is about to leave this machine.
type EndpointInfo struct {
	Host string // host[:port] as configured
	// OffHost is true when requests cross a network: the host is not loopback and not a
	// same-machine name (a single-label Docker service such as "ollama", or host.docker.internal).
	OffHost bool
	// Insecure is true when requests cross a network over plain http.
	Insecure bool
}

// ClassifyEndpoint parses a base URL and reports where it points.
func ClassifyEndpoint(rawURL string) (EndpointInfo, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return EndpointInfo{}, fmt.Errorf("invalid base_url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return EndpointInfo{}, fmt.Errorf("base_url %q must start with http:// or https://", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return EndpointInfo{}, fmt.Errorf("base_url %q has no host", rawURL)
	}

	offHost := true
	switch {
	case host == "localhost", host == "host.docker.internal":
		offHost = false
	case net.ParseIP(host) != nil:
		offHost = !net.ParseIP(host).IsLoopback()
	case !strings.Contains(host, "."):
		offHost = false // single-label name, e.g. the "ollama" service in docker compose
	}
	return EndpointInfo{Host: u.Host, OffHost: offHost, Insecure: offHost && u.Scheme == "http"}, nil
}

// Endpoint describes this role's endpoint. A role marked `remote: true` (for example an SSH
// tunnel to a GPU box that appears as localhost) is still reported as leaving the machine.
func (m ModelRoleConfig) Endpoint() EndpointInfo {
	info, _ := ClassifyEndpoint(m.BaseURL)
	return info
}

// LeavesMachine reports whether prompts for this role (which contain your source code) are
// sent to another machine.
func (m ModelRoleConfig) LeavesMachine() bool {
	if m.Remote {
		return true
	}
	return m.Endpoint().OffHost
}

// validateEndpoints rejects configurations that would send code to another machine without
// encryption, unless the operator explicitly accepts that.
func (c *Config) validateEndpoints() error {
	for role, m := range c.Models {
		if m.Adapter != "openai-compatible" && m.Adapter != "ollama" {
			continue
		}
		info, err := ClassifyEndpoint(m.BaseURL)
		if err != nil {
			return fmt.Errorf("models.%s: %w", role, err)
		}
		if info.Insecure && !m.AllowInsecureHTTP {
			return fmt.Errorf("models.%s.base_url %q would send your code to another machine over plain http. "+
				"Use https, or tunnel to localhost (for example `ssh -L 11434:localhost:11434 user@gpu-host`) and set `remote: true`, "+
				"or set `allow_insecure_http: true` if that network is private and trusted (WireGuard, Tailscale, a home LAN)", role, m.BaseURL)
		}
	}
	return nil
}
