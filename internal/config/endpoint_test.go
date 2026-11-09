package config

import (
	"strings"
	"testing"
)

func TestClassifyEndpoint(t *testing.T) {
	cases := []struct {
		url                string
		wantOffHost, wantI bool
	}{
		{"http://localhost:11434/v1", false, false},
		{"http://127.0.0.1:11434/v1", false, false},
		{"http://[::1]:11434/v1", false, false},
		{"http://ollama:11434/v1", false, false},               // docker compose service on this machine
		{"http://host.docker.internal:11434/v1", false, false}, // the Docker host, i.e. this machine
		{"https://llm.example.com/v1", true, false},
		{"http://llm.example.com/v1", true, true},
		{"http://192.168.1.20:11434/v1", true, true},   // a LAN box is another machine
		{"https://192.168.1.20:11434/v1", true, false}, // encrypted
		{"http://100.101.102.103:11434/v1", true, true},
		{"http://gpu.local:11434/v1", true, true}, // mDNS name: another machine
	}
	for _, tc := range cases {
		info, err := ClassifyEndpoint(tc.url)
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if info.OffHost != tc.wantOffHost || info.Insecure != tc.wantI {
			t.Errorf("%s: offHost=%v insecure=%v, want %v %v", tc.url, info.OffHost, info.Insecure, tc.wantOffHost, tc.wantI)
		}
	}
	for _, bad := range []string{"", "localhost:11434", "ftp://x/v1", "http:///v1"} {
		if _, err := ClassifyEndpoint(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestRemoteFlagMakesALocalLookingEndpointRemote(t *testing.T) {
	tunnel := ModelRoleConfig{BaseURL: "http://localhost:11434/v1", Remote: true}
	if !tunnel.LeavesMachine() {
		t.Fatal("an SSH tunnel marked remote must be reported as leaving the machine")
	}
	if (ModelRoleConfig{BaseURL: "http://localhost:11434/v1"}).LeavesMachine() {
		t.Fatal("plain localhost must not be reported as leaving the machine")
	}
}

func loadConfig(t *testing.T, name string) (*Config, error) {
	t.Helper()
	return Load("../../configs/" + name)
}

func TestMacProfileIsFullyLocal(t *testing.T) {
	cfg, err := loadConfig(t, "config.mac.yaml")
	if err != nil {
		t.Fatalf("mac profile should load with no environment: %v", err)
	}
	if cfg.App.Profile != "mac-local" {
		t.Fatalf("profile = %q", cfg.App.Profile)
	}
	for _, role := range []string{"lead", "scout", "investigator", "reviewer"} {
		m, ok := cfg.Models[role]
		if !ok {
			t.Fatalf("mac profile is missing role %q", role)
		}
		if m.LeavesMachine() {
			t.Fatalf("%s: the mac-local profile must never send code off this machine (%s)", role, m.BaseURL)
		}
	}
}

func TestGPUProfileRequiresExplicitSettings(t *testing.T) {
	_, err := loadConfig(t, "config.gpu.yaml")
	if err == nil {
		t.Fatal("gpu profile must not load without its variables")
	}
	for _, v := range []string{"GPU_BASE_URL", "GPU_LEAD_MODEL", "GPU_SCOUT_MODEL", "GPU_INVESTIGATOR_MODEL", "GPU_REVIEWER_MODEL"} {
		if !strings.Contains(err.Error(), v) {
			t.Errorf("error should name %s: %v", v, err)
		}
	}

	setAll := func(baseURL string) {
		t.Setenv("GPU_BASE_URL", baseURL)
		for _, v := range []string{"GPU_LEAD_MODEL", "GPU_SCOUT_MODEL", "GPU_INVESTIGATOR_MODEL", "GPU_REVIEWER_MODEL"} {
			t.Setenv(v, "some-model:tag")
		}
	}

	// An SSH tunnel looks like localhost but is still another machine.
	setAll("http://localhost:11434/v1")
	cfg, err := loadConfig(t, "config.gpu.yaml")
	if err != nil {
		t.Fatalf("tunnel to localhost should load: %v", err)
	}
	for role, m := range cfg.Models {
		if !m.LeavesMachine() {
			t.Errorf("%s: gpu profile must always report that code leaves the machine", role)
		}
	}

	setAll("https://llm.example.com/v1")
	if _, err := loadConfig(t, "config.gpu.yaml"); err != nil {
		t.Fatalf("https endpoint should load: %v", err)
	}

	// The guardrail: plain http to another machine is refused unless explicitly accepted.
	setAll("http://203.0.113.7:11434/v1")
	_, err = loadConfig(t, "config.gpu.yaml")
	if err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("plain http to a remote host must be rejected with an explanation, got: %v", err)
	}
}

func TestAllowInsecureHTTPIsAnExplicitOptIn(t *testing.T) {
	cfg := &Config{
		Research: ResearchConfig{MaxHypothesesPerJob: 1, MaxIterationsPerHypothesis: 1},
		Models: map[string]ModelRoleConfig{
			"scout":        {Adapter: "openai-compatible", BaseURL: "http://100.64.0.5:11434/v1"},
			"investigator": {Adapter: "openai-compatible", BaseURL: "http://localhost:11434/v1"},
			"reviewer":     {Adapter: "openai-compatible", BaseURL: "http://localhost:11434/v1"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("plain http to a private-network address must need an explicit opt-in")
	}
	m := cfg.Models["scout"]
	m.AllowInsecureHTTP = true
	cfg.Models["scout"] = m
	if err := cfg.Validate(); err != nil {
		t.Fatalf("opt-in should be accepted: %v", err)
	}
}

// The profiles that already shipped must keep working.
func TestExistingConfigsStillLoad(t *testing.T) {
	for _, name := range []string{"config.example.yaml", "config.docker.yaml", "config.e2e.yaml", "config.local.yaml"} {
		if _, err := loadConfig(t, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
