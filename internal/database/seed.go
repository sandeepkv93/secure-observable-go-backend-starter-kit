package database

import (
	"fmt"
	"strings"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

	"gorm.io/gorm"
)

var defaultPermissions = []domain.Permission{
	{Resource: "users", Action: "read"},
	{Resource: "users", Action: "write"},
	{Resource: "roles", Action: "read"},
	{Resource: "roles", Action: "write"},
	{Resource: "permissions", Action: "read"},
}

func Seed(db *gorm.DB, bootstrapAdminEmail string) error {
	for _, p := range defaultPermissions {
		if err := db.Where("resource = ? AND action = ?", p.Resource, p.Action).FirstOrCreate(&p).Error; err != nil {
			return err
		}
	}

	userRole := domain.Role{Name: "user", Description: "Default user role"}
	adminRole := domain.Role{Name: "admin", Description: "Administrator role"}
	if err := db.Where("name = ?", userRole.Name).FirstOrCreate(&userRole).Error; err != nil {
		return err
	}
	if err := db.Where("name = ?", adminRole.Name).FirstOrCreate(&adminRole).Error; err != nil {
		return err
	}

	var perms []domain.Permission
	if err := db.Where("resource IN ?", []string{"users", "roles", "permissions"}).Find(&perms).Error; err != nil {
		return err
	}
	if len(perms) > 0 {
		if err := db.Model(&adminRole).Association("Permissions").Replace(&perms); err != nil {
			return err
		}
	}

	email := strings.TrimSpace(strings.ToLower(bootstrapAdminEmail))
	if email == "" {
		return nil
	}

	var u domain.User
	if err := db.Where("email = ?", email).First(&u).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil
		}
		return err
	}

	if err := db.Model(&u).Association("Roles").Append(&adminRole); err != nil {
		return fmt.Errorf("assign bootstrap admin role: %w", err)
	}

	return nil
}
