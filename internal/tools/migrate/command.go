package migrate

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/database"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/common"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/ui"
	"gorm.io/gorm"
)

type options struct {
	envFile string
	timeout time.Duration
	ci      bool
}

func NewRootCommand() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Database migration tooling",
	}
	cmd.PersistentFlags().StringVar(&opts.envFile, "env-file", ".env", "path to env file")
	cmd.PersistentFlags().DurationVar(&opts.timeout, "timeout", 30*time.Second, "operation timeout")
	cmd.PersistentFlags().BoolVar(&opts.ci, "ci", false, "non-interactive machine-readable output")

	cmd.AddCommand(
		newUpCommand(opts),
		newStatusCommand(opts),
		newPlanCommand(opts),
	)
	return cmd
}

func newUpCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply schema migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "migrate up", func(ctx context.Context) ([]string, error) {
				cfg, db, err := loadConfigDB(opts.envFile)
				if err != nil {
					return nil, err
				}
				sqlDB, _ := db.DB()
				defer func() { _ = sqlDB.Close() }()

				if err := database.Migrate(db); err != nil {
					return nil, err
				}
				return []string{"schema migration applied", "database: connected", "service: " + cfg.OTELServiceName}, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "migrate up", details, err)
			}
			if err != nil {
				os.Exit(3)
			}
			return nil
		},
	}
}

func newStatusCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check migration prerequisites",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "migrate status", func(ctx context.Context) ([]string, error) {
				cfg, db, err := loadConfigDB(opts.envFile)
				if err != nil {
					return nil, err
				}
				sqlDB, _ := db.DB()
				defer func() { _ = sqlDB.Close() }()
				if err := sqlDB.PingContext(ctx); err != nil {
					return nil, fmt.Errorf("db ping: %w", err)
				}
				return []string{"database reachable", "service: " + cfg.OTELServiceName, "migrations: ready"}, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "migrate status", details, err)
			}
			if err != nil {
				os.Exit(3)
			}
			return nil
		},
	}
}

func newPlanCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "plan",
		Short: "Show migration plan (dry-run)",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "migrate plan", func(ctx context.Context) ([]string, error) {
				_, db, err := loadConfigDB(opts.envFile)
				if err != nil {
					return nil, err
				}
				sqlDB, _ := db.DB()
				defer func() { _ = sqlDB.Close() }()
				if err := sqlDB.PingContext(ctx); err != nil {
					return nil, fmt.Errorf("db ping: %w", err)
				}
				return []string{
					"would apply AutoMigrate for domain models",
					"user, role, permission, user_role, role_permission, oauth_account, session",
					"no mutation executed in plan mode",
				}, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "migrate plan", details, err)
			}
			if err != nil {
				os.Exit(3)
			}
			return nil
		},
	}
}

func run(opts *options, title string, fn func(context.Context) ([]string, error)) ([]string, error) {
	if opts.ci {
		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		defer cancel()
		return fn(ctx)
	}
	return ui.Run(title, fn)
}

func loadConfigDB(envFile string) (*config.Config, *gorm.DB, error) {
	if err := common.LoadEnvFile(envFile); err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	db, err := database.Open(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, db, nil
}
