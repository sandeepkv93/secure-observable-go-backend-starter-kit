package di

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/router"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
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
	cfg := &config.Config{CORSAllowedOrigins: []string{"http://localhost:3000"}, AuthRateLimitPerMin: 10, APIRateLimitPerMin: 100, OTELMetricsEnabled: true}
	dep := provideRouterDependencies(nil, nil, nil, nil, nil, nil, nil, cfg)
	if dep.AuthRateLimitRPM != 10 || dep.APIRateLimitRPM != 100 {
		t.Fatalf("unexpected rate limits: %+v", dep)
	}
	if !dep.EnableOTelHTTP {
		t.Fatal("expected otel http enabled")
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
	runtime := &observability.Runtime{}

	app := provideApp(cfg, logger, srv, runtime)
	if app == nil {
		t.Fatal("expected app")
	}
	if app.Config != cfg || app.Logger != logger || app.Server != srv || app.Observability != runtime {
		t.Fatal("app dependencies not wired as expected")
	}
}
