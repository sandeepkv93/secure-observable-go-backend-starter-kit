package di

import (
	"log/slog"
	"net/http"
	"testing"

	"go-oauth-rbac-service/internal/config"
	"go-oauth-rbac-service/internal/http/router"
)

func TestProvideHTTPServer(t *testing.T) {
	cfg := &config.Config{HTTPPort: "9999"}
	srv := provideHTTPServer(cfg, nil)
	if srv.Addr != ":9999" {
		t.Fatalf("unexpected addr: %s", srv.Addr)
	}
	if srv.ReadTimeout.Seconds() != 10 {
		t.Fatalf("unexpected read timeout: %v", srv.ReadTimeout)
	}
}

func TestProvideRouterDependencies(t *testing.T) {
	cfg := &config.Config{CORSAllowedOrigins: []string{"http://localhost:3000"}, AuthRateLimitPerMin: 10, APIRateLimitPerMin: 100}
	dep := provideRouterDependencies(nil, nil, nil, nil, nil, cfg)
	if dep.AuthRateLimitRPM != 10 || dep.APIRateLimitRPM != 100 {
		t.Fatalf("unexpected rate limits: %+v", dep)
	}
	if len(dep.CORSOrigins) != 1 || dep.CORSOrigins[0] != "http://localhost:3000" {
		t.Fatalf("unexpected cors origins: %+v", dep.CORSOrigins)
	}
	_ = router.Dependencies(dep)
}

func TestProvideApp(t *testing.T) {
	cfg := &config.Config{HTTPPort: "8080"}
	logger := slog.Default()
	srv := &http.Server{Addr: ":8080"}
	ready := &observabilityReady{}

	app := provideApp(cfg, logger, srv, ready)
	if app == nil {
		t.Fatal("expected app")
	}
	if app.Config != cfg || app.Logger != logger || app.Server != srv {
		t.Fatal("app dependencies not wired as expected")
	}
}

func TestInitializeObservability(t *testing.T) {
	ready, err := initializeObservability()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ready == nil {
		t.Fatal("expected observabilityReady")
	}
}
