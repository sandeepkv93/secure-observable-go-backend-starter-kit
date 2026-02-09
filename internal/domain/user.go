package domain

import "time"

type User struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Email       string    `gorm:"uniqueIndex;size:255;not null" json:"email"`
	Name        string    `gorm:"size:255;not null" json:"name"`
	AvatarURL   string    `gorm:"size:1024" json:"avatar_url"`
	Status      string    `gorm:"size:32;not null;default:active;index:idx_users_status" json:"status"`
	LastLoginAt time.Time `json:"last_login_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Roles       []Role    `gorm:"many2many:user_roles" json:"roles,omitempty"`
}
