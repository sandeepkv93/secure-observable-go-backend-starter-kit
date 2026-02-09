package loadgen

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	BaseURL     string
	Profile     string
	Duration    time.Duration
	RPS         int
	Concurrency int
	Seed        int64
}

type Result struct {
	TotalRequests int64
	Failures      int64
	Status2xx     int64
	Status4xx     int64
	Status5xx     int64
}

func Run(ctx context.Context, cfg Config) (Result, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	if cfg.Duration <= 0 {
		cfg.Duration = 10 * time.Second
	}
	if cfg.RPS <= 0 {
		cfg.RPS = 15
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}

	client := &http.Client{Timeout: 5 * time.Second}
	endpoints := endpointsForProfile(cfg.Profile)
	if len(endpoints) == 0 {
		return Result{}, fmt.Errorf("unknown profile: %s", cfg.Profile)
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	var total, failures, s2xx, s4xx, s5xx int64
	jobs := make(chan string, cfg.Concurrency*2)
	wg := sync.WaitGroup{}

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for path := range jobs {
				method := http.MethodGet
				if strings.Contains(path, "/refresh") {
					method = http.MethodPost
				}
				req, err := http.NewRequestWithContext(ctx, method, cfg.BaseURL+path, nil)
				if err != nil {
					atomic.AddInt64(&failures, 1)
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&failures, 1)
					continue
				}
				_ = resp.Body.Close()
				atomic.AddInt64(&total, 1)
				switch {
				case resp.StatusCode >= 200 && resp.StatusCode < 300:
					atomic.AddInt64(&s2xx, 1)
				case resp.StatusCode >= 400 && resp.StatusCode < 500:
					atomic.AddInt64(&s4xx, 1)
				case resp.StatusCode >= 500:
					atomic.AddInt64(&s5xx, 1)
				}
			}
		}(i)
	}

	ticker := time.NewTicker(time.Second / time.Duration(cfg.RPS))
	defer ticker.Stop()
	i := 0
	for {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return Result{TotalRequests: total, Failures: failures, Status2xx: s2xx, Status4xx: s4xx, Status5xx: s5xx}, nil
		case <-ticker.C:
			jobs <- endpoints[i%len(endpoints)]
			i++
		}
	}
}

func endpointsForProfile(profile string) []string {
	switch strings.ToLower(profile) {
	case "", "mixed":
		return []string{"/api/v1/auth/google/login", "/api/v1/auth/google/callback?state=bad&code=x", "/api/v1/auth/refresh"}
	case "auth":
		return []string{"/api/v1/auth/google/login", "/api/v1/auth/google/callback?state=bad&code=x", "/api/v1/auth/refresh"}
	case "error-heavy":
		return []string{"/api/v1/auth/google/callback?state=bad&code=x", "/api/v1/auth/refresh"}
	default:
		return nil
	}
}
