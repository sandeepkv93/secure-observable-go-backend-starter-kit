package obscheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/common"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/loadgen"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/ui"
)

type options struct {
	grafanaURL      string
	grafanaUser     string
	grafanaPassword string
	serviceName     string
	window          time.Duration
	ci              bool
	baseURL         string
}

func NewRootCommand() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{Use: "obscheck", Short: "Verify metrics, traces and logs correlation"}
	cmd.PersistentFlags().StringVar(&opts.grafanaURL, "grafana-url", "http://localhost:3000", "Grafana base URL")
	cmd.PersistentFlags().StringVar(&opts.grafanaUser, "grafana-user", "admin", "Grafana username")
	cmd.PersistentFlags().StringVar(&opts.grafanaPassword, "grafana-password", "admin", "Grafana password")
	cmd.PersistentFlags().StringVar(&opts.serviceName, "service-name", "secure-observable-go-backend-starter-kit", "OTel service name")
	cmd.PersistentFlags().DurationVar(&opts.window, "window", 20*time.Minute, "query lookback window")
	cmd.PersistentFlags().BoolVar(&opts.ci, "ci", false, "non-interactive machine-readable output")
	cmd.PersistentFlags().StringVar(&opts.baseURL, "base-url", "http://localhost:8080", "API base URL for traffic")
	cmd.AddCommand(newRunCommand(opts))
	return cmd
}

func newRunCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Generate traffic and validate exemplar->trace->log path",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "obscheck run", func(ctx context.Context) ([]string, error) {
				lgRes, err := loadgen.Run(ctx, loadgen.Config{
					BaseURL:     opts.baseURL,
					Profile:     "mixed",
					Duration:    6 * time.Second,
					RPS:         20,
					Concurrency: 6,
					Seed:        42,
				})
				if err != nil {
					return nil, err
				}
				details := []string{fmt.Sprintf("traffic generated total=%d failures=%d", lgRes.TotalRequests, lgRes.Failures)}
				time.Sleep(8 * time.Second)

				traceID, err := fetchTraceIDFromExemplar(ctx, *opts)
				if err != nil {
					return details, err
				}
				details = append(details, "exemplar trace_id="+traceID)

				if err := verifyTempoTrace(ctx, *opts, traceID); err != nil {
					return details, err
				}
				details = append(details, "tempo trace lookup: ok")

				if err := verifyLokiTraceLogs(ctx, *opts, traceID); err != nil {
					return details, err
				}
				details = append(details, "loki trace correlation: ok")
				return details, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "obscheck run", details, err)
			}
			if err != nil {
				os.Exit(4)
			}
			return nil
		},
	}
}

func run(opts *options, title string, fn func(context.Context) ([]string, error)) ([]string, error) {
	if opts.ci {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		return fn(ctx)
	}
	return ui.Run(title, fn)
}

func grafanaGET(ctx context.Context, opts options, path string) ([]byte, error) {
	u, err := url.Parse(opts.grafanaURL)
	if err != nil {
		return nil, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(opts.grafanaUser, opts.grafanaPassword)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("grafana request failed: %s", resp.Status)
	}
	return ioReadAll(resp.Body)
}

func fetchTraceIDFromExemplar(ctx context.Context, opts options) (string, error) {
	start := time.Now().Add(-opts.window).Unix()
	end := time.Now().Unix()
	path := fmt.Sprintf("/api/datasources/proxy/1/api/v1/query_exemplars?query=auth_request_duration_seconds_bucket&start=%d&end=%d", start, end)
	body, err := grafanaGET(ctx, opts, path)
	if err != nil {
		return "", err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	data, _ := payload["data"].([]any)
	for _, series := range data {
		sm, _ := series.(map[string]any)
		exemplars, _ := sm["exemplars"].([]any)
		for _, e := range exemplars {
			em, _ := e.(map[string]any)
			labels, _ := em["labels"].(map[string]any)
			if tid, ok := labels["trace_id"].(string); ok && len(tid) == 32 {
				return tid, nil
			}
		}
	}
	return "", fmt.Errorf("no trace_id exemplar found")
}

func verifyTempoTrace(ctx context.Context, opts options, traceID string) error {
	path := fmt.Sprintf("/api/datasources/proxy/3/api/traces/%s", traceID)
	body, err := grafanaGET(ctx, opts, path)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}
	batches, _ := payload["batches"].([]any)
	if len(batches) == 0 {
		return fmt.Errorf("tempo trace has no batches")
	}
	return nil
}

func verifyLokiTraceLogs(ctx context.Context, opts options, traceID string) error {
	nowNS := time.Now().UnixNano()
	startNS := nowNS - int64(30*time.Minute)
	q := url.QueryEscape(fmt.Sprintf("{service_name=\"%s\"} |= \"trace_id=%s\"", opts.serviceName, traceID))
	path := fmt.Sprintf("/api/datasources/proxy/2/loki/api/v1/query_range?query=%s&start=%d&end=%d&limit=1&direction=backward", q, startNS, nowNS)
	body, err := grafanaGET(ctx, opts, path)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}
	data, _ := payload["data"].(map[string]any)
	result, _ := data["result"].([]any)
	if len(result) == 0 {
		return fmt.Errorf("no correlated loki logs found for trace_id %s", traceID)
	}
	return nil
}

func ioReadAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }
