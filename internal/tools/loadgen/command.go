package loadgen

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/common"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/ui"
)

type options struct {
	baseURL     string
	profile     string
	duration    time.Duration
	rps         int
	concurrency int
	seed        int64
	ci          bool
}

func NewRootCommand() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{Use: "loadgen", Short: "Generate traffic for observability validation"}
	cmd.PersistentFlags().StringVar(&opts.baseURL, "base-url", "http://localhost:8080", "API base URL")
	cmd.PersistentFlags().StringVar(&opts.profile, "profile", "mixed", "traffic profile: auth|mixed|error-heavy")
	cmd.PersistentFlags().DurationVar(&opts.duration, "duration", 15*time.Second, "traffic duration")
	cmd.PersistentFlags().IntVar(&opts.rps, "rps", 20, "requests per second")
	cmd.PersistentFlags().IntVar(&opts.concurrency, "concurrency", 6, "concurrent workers")
	cmd.PersistentFlags().Int64Var(&opts.seed, "seed", 42, "random seed")
	cmd.PersistentFlags().BoolVar(&opts.ci, "ci", false, "non-interactive machine-readable output")
	cmd.AddCommand(newRunCommand(opts))
	return cmd
}

func newRunCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run load generation",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "loadgen run", func(ctx context.Context) ([]string, error) {
				res, err := Run(ctx, Config{
					BaseURL:     opts.baseURL,
					Profile:     opts.profile,
					Duration:    opts.duration,
					RPS:         opts.rps,
					Concurrency: opts.concurrency,
					Seed:        opts.seed,
				})
				if err != nil {
					return nil, err
				}
				return []string{
					fmt.Sprintf("total_requests=%d", res.TotalRequests),
					fmt.Sprintf("failures=%d", res.Failures),
					fmt.Sprintf("status_2xx=%d", res.Status2xx),
					fmt.Sprintf("status_4xx=%d", res.Status4xx),
					fmt.Sprintf("status_5xx=%d", res.Status5xx),
				}, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "loadgen run", details, err)
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
		ctx, cancel := context.WithTimeout(context.Background(), opts.duration+15*time.Second)
		defer cancel()
		return fn(ctx)
	}
	return ui.Run(title, fn)
}
