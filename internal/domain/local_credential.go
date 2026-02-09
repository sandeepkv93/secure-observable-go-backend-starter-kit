package domain

import "time"

type LocalCredential struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	UserID          uint       `gorm:"uniqueIndex;not null" json:"user_id"`
	PasswordHash    string     `gorm:"size:1024;not null" json:"-"`
	EmailVerified   bool       `gorm:"not null;default:false" json:"email_verified"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
