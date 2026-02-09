package seed

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gorm.io/gorm"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/database"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/common"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/ui"
)

type options struct {
	envFile             string
	bootstrapAdminEmail string
	ci                  bool
}

func NewRootCommand() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{Use: "seed", Short: "Database seed tooling"}
	cmd.PersistentFlags().StringVar(&opts.envFile, "env-file", ".env", "path to env file")
	cmd.PersistentFlags().StringVar(&opts.bootstrapAdminEmail, "bootstrap-admin-email", "", "override bootstrap admin email")
	cmd.PersistentFlags().BoolVar(&opts.ci, "ci", false, "non-interactive machine-readable output")
	cmd.AddCommand(newApplyCommand(opts), newDryRunCommand(opts), newVerifyLocalEmailCommand(opts))
	return cmd
}

func newApplyCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "apply",
		Short: "Apply default seed data",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "seed apply", func(ctx context.Context) ([]string, error) {
				cfg, db, err := loadConfigDB(opts.envFile)
				if err != nil {
					return nil, err
				}
				email := cfg.BootstrapAdminEmail
				if opts.bootstrapAdminEmail != "" {
					email = opts.bootstrapAdminEmail
				}
				if err := database.Seed(db, email); err != nil {
					return nil, err
				}
				details := []string{"seeded default roles and permissions"}
				if email != "" {
					details = append(details, "bootstrap admin role assignment attempted for: "+email)
				}
				return details, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "seed apply", details, err)
			}
			if err != nil {
				os.Exit(3)
			}
			return nil
		},
	}
}

func newDryRunCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "dry-run",
		Short: "Show what seeding would do",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "seed dry-run", func(ctx context.Context) ([]string, error) {
				cfg, _, err := loadConfigDB(opts.envFile)
				if err != nil {
					return nil, err
				}
				email := cfg.BootstrapAdminEmail
				if opts.bootstrapAdminEmail != "" {
					email = opts.bootstrapAdminEmail
				}
				details := []string{
					"would ensure permissions: users:read, users:write, roles:read, roles:write, permissions:read",
					"would ensure roles: user, admin",
					"would map admin role to all default permissions",
				}
				if email != "" {
					details = append(details, fmt.Sprintf("would assign admin role to user if present: %s", email))
				}
				return details, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "seed dry-run", details, err)
			}
			if err != nil {
				os.Exit(3)
			}
			return nil
		},
	}
}

func newVerifyLocalEmailCommand(opts *options) *cobra.Command {
	var email string
	cmd := &cobra.Command{
		Use:   "verify-local-email",
		Short: "Mark local credential email as verified",
		RunE: func(cmd *cobra.Command, args []string) error {
			details, err := run(opts, "seed verify-local-email", func(ctx context.Context) ([]string, error) {
				if strings.TrimSpace(email) == "" {
					return nil, fmt.Errorf("email is required")
				}
				_, db, err := loadConfigDB(opts.envFile)
				if err != nil {
					return nil, err
				}
				if err := database.VerifyLocalEmail(db, email); err != nil {
					return nil, err
				}
				return []string{fmt.Sprintf("marked local email verified: %s", strings.TrimSpace(strings.ToLower(email)))}, nil
			})
			if opts.ci {
				common.PrintCIResult(err == nil, "seed verify-local-email", details, err)
			}
			if err != nil {
				os.Exit(3)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "email to mark verified")
	return cmd
}

func run(opts *options, title string, fn func(context.Context) ([]string, error)) ([]string, error) {
	if opts.ci {
		return fn(context.Background())
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
