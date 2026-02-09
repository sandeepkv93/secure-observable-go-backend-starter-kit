package repository

import (
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

	"gorm.io/gorm"
)

type UserRepository interface {
	FindByID(id uint) (*domain.User, error)
	FindByEmail(email string) (*domain.User, error)
	Create(user *domain.User) error
	Update(user *domain.User) error
	List() ([]domain.User, error)
	SetRoles(userID uint, roleIDs []uint) error
	AddRole(userID, roleID uint) error
}

type GormUserRepository struct{ db *gorm.DB }

func NewUserRepository(db *gorm.DB) UserRepository { return &GormUserRepository{db: db} }

func (r *GormUserRepository) FindByID(id uint) (*domain.User, error) {
	var u domain.User
	err := r.db.Preload("Roles.Permissions").First(&u, id).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *GormUserRepository) FindByEmail(email string) (*domain.User, error) {
	var u domain.User
	err := r.db.Preload("Roles.Permissions").Where("email = ?", email).First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *GormUserRepository) Create(user *domain.User) error { return r.db.Create(user).Error }
func (r *GormUserRepository) Update(user *domain.User) error { return r.db.Save(user).Error }

func (r *GormUserRepository) List() ([]domain.User, error) {
	var users []domain.User
	err := r.db.Preload("Roles").Find(&users).Error
	return users, err
}

func (r *GormUserRepository) SetRoles(userID uint, roleIDs []uint) error {
	var roles []domain.Role
	if len(roleIDs) > 0 {
		if err := r.db.Where("id IN ?", roleIDs).Find(&roles).Error; err != nil {
			return err
		}
	}
	u := domain.User{ID: userID}
	return r.db.Model(&u).Association("Roles").Replace(roles)
}

func (r *GormUserRepository) AddRole(userID, roleID uint) error {
	u := domain.User{ID: userID}
	role := domain.Role{ID: roleID}
	return r.db.Model(&u).Association("Roles").Append(&role)
}
