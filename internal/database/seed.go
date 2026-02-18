package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"

	"gorm.io/gorm"
)

var defaultPermissions = []domain.Permission{
	{Resource: "users", Action: "read"},
	{Resource: "users", Action: "write"},
	{Resource: "roles", Action: "read"},
	{Resource: "roles", Action: "write"},
	{Resource: "permissions", Action: "read"},
	{Resource: "permissions", Action: "write"},
	{Resource: "feature_flags", Action: "read"},
	{Resource: "feature_flags", Action: "write"},
	{Resource: "products", Action: "read"},
	{Resource: "products", Action: "write"},
	{Resource: "products", Action: "delete"},
}

type RBACSyncReport struct {
	CreatedPermissions int  `json:"created_permissions"`
	CreatedRoles       int  `json:"created_roles"`
	BoundPermissions   int  `json:"bound_permissions"`
	Noop               bool `json:"noop"`
}

func Seed(db *gorm.DB, bootstrapAdminEmail string) error {
	_, err := SeedSync(db, bootstrapAdminEmail)
	return err
}

func SeedSync(db *gorm.DB, bootstrapAdminEmail string) (*RBACSyncReport, error) {
	start := time.Now()
	defer func() {
		observability.RecordDatabaseStartupDuration(context.Background(), "seed", time.Since(start))
	}()

	report := &RBACSyncReport{}

	for _, p := range defaultPermissions {
		res := db.Where("resource = ? AND action = ?", p.Resource, p.Action).FirstOrCreate(&p)
		if res.Error != nil {
			observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
			return nil, res.Error
		}
		if res.RowsAffected > 0 {
			report.CreatedPermissions++
		}
	}

	userRole := domain.Role{Name: "user", Description: "Default user role"}
	adminRole := domain.Role{Name: "admin", Description: "Administrator role"}
	res := db.Where("name = ?", userRole.Name).FirstOrCreate(&userRole)
	if res.Error != nil {
		observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
		return nil, res.Error
	}
	if res.RowsAffected > 0 {
		report.CreatedRoles++
	}
	res = db.Where("name = ?", adminRole.Name).FirstOrCreate(&adminRole)
	if res.Error != nil {
		observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
		return nil, res.Error
	}
	if res.RowsAffected > 0 {
		report.CreatedRoles++
	}

	var perms []domain.Permission
	if err := db.Where("resource IN ?", []string{"users", "roles", "permissions", "feature_flags", "products"}).Find(&perms).Error; err != nil {
		observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
		return nil, err
	}
	if len(perms) > 0 {
		var before domain.Role
		if err := db.Preload("Permissions").Where("id = ?", adminRole.ID).First(&before).Error; err != nil {
			observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
			return nil, err
		}
		beforeSet := make(map[uint]struct{}, len(before.Permissions))
		for _, p := range before.Permissions {
			beforeSet[p.ID] = struct{}{}
		}
		if err := db.Model(&adminRole).Association("Permissions").Replace(&perms); err != nil {
			observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
			return nil, err
		}
		for _, p := range perms {
			if _, ok := beforeSet[p.ID]; !ok {
				report.BoundPermissions++
			}
		}
	}

	email := strings.TrimSpace(strings.ToLower(bootstrapAdminEmail))
	if email != "" {
		var u domain.User
		if err := db.Where("email = ?", email).First(&u).Error; err != nil {
			if err != gorm.ErrRecordNotFound {
				observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
				return nil, err
			}
		} else {
			var count int64
			if err := db.Table("user_roles").Where("user_id = ? AND role_id = ?", u.ID, adminRole.ID).Count(&count).Error; err != nil {
				observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
				return nil, err
			}
			if count == 0 {
				if err := db.Model(&u).Association("Roles").Append(&adminRole); err != nil {
					observability.RecordDatabaseStartupEvent(context.Background(), "seed", "error")
					return nil, fmt.Errorf("assign bootstrap admin role: %w", err)
				}
				report.BoundPermissions++
			}
		}
	}

	report.Noop = report.CreatedPermissions == 0 && report.CreatedRoles == 0 && report.BoundPermissions == 0
	observability.RecordDatabaseStartupEvent(context.Background(), "seed", "success")
	return report, nil
}

func VerifyLocalEmail(db *gorm.DB, email string) error {
	normalized := strings.TrimSpace(strings.ToLower(email))
	if normalized == "" {
		return fmt.Errorf("email is required")
	}
	var u domain.User
	if err := db.Where("email = ?", normalized).First(&u).Error; err != nil {
		return err
	}
	now := time.Now().UTC()
	tx := db.Model(&domain.LocalCredential{}).Where("user_id = ?", u.ID).
		Updates(map[string]any{"email_verified": true, "email_verified_at": &now})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
