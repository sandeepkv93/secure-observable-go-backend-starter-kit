package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	repogomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/repository/gomock"
	"go.uber.org/mock/gomock"
)

func TestFeatureFlagServiceEvaluatePrecedence(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockFeatureFlagRepository(ctrl)
	repo.EXPECT().FindFlagByKey("new_checkout").AnyTimes().Return(&domain.FeatureFlag{
		ID:      1,
		Key:     "new_checkout",
		Enabled: false,
		Rules: []domain.FeatureFlagRule{
			{ID: 1, FeatureFlagID: 1, Type: FeatureFlagRuleTypePercent, Percentage: 100, Enabled: false, Priority: 50},
			{ID: 2, FeatureFlagID: 1, Type: FeatureFlagRuleTypeEnvironment, MatchValue: "prod", Enabled: false, Priority: 40},
			{ID: 3, FeatureFlagID: 1, Type: FeatureFlagRuleTypeRole, MatchValue: "admin", Enabled: true, Priority: 30},
			{ID: 4, FeatureFlagID: 1, Type: FeatureFlagRuleTypeUser, MatchValue: "42", Enabled: false, Priority: 20},
		},
	}, nil)
	svc := NewFeatureFlagService(repo, NewInMemoryFeatureFlagEvaluationCacheStore())

	res, err := svc.EvaluateByKey(context.Background(), "new_checkout", FeatureFlagEvaluationContext{
		UserID:      42,
		Roles:       []string{"admin"},
		Environment: "prod",
	})
	if err != nil {
		t.Fatalf("evaluate by key: %v", err)
	}
	if res.Source != "rule:user" || res.Enabled {
		t.Fatalf("expected user rule to win with false, got source=%s enabled=%v", res.Source, res.Enabled)
	}

	res, err = svc.EvaluateByKey(context.Background(), "new_checkout", FeatureFlagEvaluationContext{
		UserID:      9,
		Roles:       []string{"admin"},
		Environment: "prod",
	})
	if err != nil {
		t.Fatalf("evaluate by key role branch: %v", err)
	}
	if res.Source != "rule:role" || !res.Enabled {
		t.Fatalf("expected role rule to win with true, got source=%s enabled=%v", res.Source, res.Enabled)
	}

	res, err = svc.EvaluateByKey(context.Background(), "new_checkout", FeatureFlagEvaluationContext{
		UserID:      10,
		Roles:       []string{"member"},
		Environment: "prod",
	})
	if err != nil {
		t.Fatalf("evaluate by key env branch: %v", err)
	}
	if res.Source != "rule:environment" || res.Enabled {
		t.Fatalf("expected environment rule to win with false, got source=%s enabled=%v", res.Source, res.Enabled)
	}
}

func TestFeatureFlagServiceRuleValidation(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockFeatureFlagRepository(ctrl)
	repo.EXPECT().FindFlagByID(uint(1)).AnyTimes().Return(&domain.FeatureFlag{ID: 1, Key: "k"}, nil)
	svc := NewFeatureFlagService(repo, NewNoopFeatureFlagEvaluationCacheStore())

	err := svc.CreateRule(context.Background(), &domain.FeatureFlagRule{FeatureFlagID: 1, Type: "percent", Percentage: 120})
	if !errors.Is(err, ErrFeatureFlagInvalidRuleValue) {
		t.Fatalf("expected invalid rule value, got %v", err)
	}

	err = svc.CreateRule(context.Background(), &domain.FeatureFlagRule{FeatureFlagID: 1, Type: "unknown", MatchValue: "x"})
	if !errors.Is(err, ErrFeatureFlagInvalidRuleType) {
		t.Fatalf("expected invalid rule type, got %v", err)
	}
}

func TestStablePercentBucketDistribution(t *testing.T) {
	const sampleSize = 10000
	const pct = 50
	enabled := 0
	rule := domain.FeatureFlagRule{FeatureFlagID: 7, Type: FeatureFlagRuleTypePercent, Percentage: pct}
	for userID := uint(1); userID <= sampleSize; userID++ {
		if matchesRule(rule, FeatureFlagEvaluationContext{UserID: userID}) {
			enabled++
		}
	}
	if enabled < 4700 || enabled > 5300 {
		t.Fatalf("expected ~50%% rollout distribution, got enabled=%d/%d", enabled, sampleSize)
	}
}

func TestFeatureFlagServiceCRUDWithGeneratedMocks(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockFeatureFlagRepository(ctrl)
	svc := NewFeatureFlagService(repo, NewNoopFeatureFlagEvaluationCacheStore())

	flags := map[uint]domain.FeatureFlag{}
	nextID := uint(1)

	repo.EXPECT().CreateFlag(gomock.AssignableToTypeOf(&domain.FeatureFlag{})).DoAndReturn(func(flag *domain.FeatureFlag) error {
		if flag.ID == 0 {
			flag.ID = nextID
			nextID++
		}
		flags[flag.ID] = *flag
		return nil
	})
	repo.EXPECT().FindFlagByID(gomock.Any()).DoAndReturn(func(id uint) (*domain.FeatureFlag, error) {
		f, ok := flags[id]
		if !ok {
			return nil, repository.ErrFeatureFlagNotFound
		}
		cp := f
		return &cp, nil
	}).AnyTimes()
	repo.EXPECT().UpdateFlag(gomock.AssignableToTypeOf(&domain.FeatureFlag{})).DoAndReturn(func(flag *domain.FeatureFlag) error {
		if _, ok := flags[flag.ID]; !ok {
			return repository.ErrFeatureFlagNotFound
		}
		flags[flag.ID] = *flag
		return nil
	})
	repo.EXPECT().DeleteFlag(gomock.Any()).DoAndReturn(func(id uint) error {
		if _, ok := flags[id]; !ok {
			return repository.ErrFeatureFlagNotFound
		}
		delete(flags, id)
		return nil
	})

	flag := &domain.FeatureFlag{Key: "k1", Description: "flag one", Enabled: true}
	if err := svc.CreateFlag(context.Background(), flag); err != nil {
		t.Fatalf("CreateFlag: %v", err)
	}

	loaded, err := svc.GetFlagByID(context.Background(), flag.ID)
	if err != nil {
		t.Fatalf("GetFlagByID: %v", err)
	}
	if loaded.Key != "k1" {
		t.Fatalf("unexpected loaded flag: %+v", loaded)
	}

	loaded.Description = "flag one updated"
	if err := svc.UpdateFlag(context.Background(), loaded); err != nil {
		t.Fatalf("UpdateFlag: %v", err)
	}

	if err := svc.DeleteFlag(context.Background(), loaded.ID); err != nil {
		t.Fatalf("DeleteFlag: %v", err)
	}
}
