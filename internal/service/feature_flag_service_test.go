package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
)

type stubFeatureFlagRepo struct {
	flags map[uint]domain.FeatureFlag
}

func (s *stubFeatureFlagRepo) ListFlags() ([]domain.FeatureFlag, error) {
	out := make([]domain.FeatureFlag, 0, len(s.flags))
	for _, f := range s.flags {
		out = append(out, f)
	}
	return out, nil
}

func (s *stubFeatureFlagRepo) FindFlagByID(id uint) (*domain.FeatureFlag, error) {
	f, ok := s.flags[id]
	if !ok {
		return nil, repository.ErrFeatureFlagNotFound
	}
	cp := f
	return &cp, nil
}

func (s *stubFeatureFlagRepo) FindFlagByKey(key string) (*domain.FeatureFlag, error) {
	for _, f := range s.flags {
		if f.Key == key {
			cp := f
			return &cp, nil
		}
	}
	return nil, repository.ErrFeatureFlagNotFound
}

func (s *stubFeatureFlagRepo) CreateFlag(flag *domain.FeatureFlag) error {
	if s.flags == nil {
		s.flags = map[uint]domain.FeatureFlag{}
	}
	if flag.ID == 0 {
		flag.ID = nextFeatureFlagID(s.flags)
	}
	s.flags[flag.ID] = *flag
	return nil
}

func (s *stubFeatureFlagRepo) UpdateFlag(flag *domain.FeatureFlag) error {
	if _, ok := s.flags[flag.ID]; !ok {
		return repository.ErrFeatureFlagNotFound
	}
	s.flags[flag.ID] = *flag
	return nil
}

func (s *stubFeatureFlagRepo) DeleteFlag(id uint) error {
	if _, ok := s.flags[id]; !ok {
		return repository.ErrFeatureFlagNotFound
	}
	delete(s.flags, id)
	return nil
}

func (s *stubFeatureFlagRepo) ListRules(flagID uint) ([]domain.FeatureFlagRule, error) {
	f, ok := s.flags[flagID]
	if !ok {
		return nil, repository.ErrFeatureFlagNotFound
	}
	return append([]domain.FeatureFlagRule(nil), f.Rules...), nil
}

func (s *stubFeatureFlagRepo) CreateRule(rule *domain.FeatureFlagRule) error {
	f, ok := s.flags[rule.FeatureFlagID]
	if !ok {
		return repository.ErrFeatureFlagNotFound
	}
	rule.ID = nextFeatureFlagRuleID(f.Rules)
	f.Rules = append(f.Rules, *rule)
	s.flags[rule.FeatureFlagID] = f
	return nil
}

func (s *stubFeatureFlagRepo) UpdateRule(rule *domain.FeatureFlagRule) error {
	f, ok := s.flags[rule.FeatureFlagID]
	if !ok {
		return repository.ErrFeatureFlagNotFound
	}
	for i := range f.Rules {
		if f.Rules[i].ID == rule.ID {
			f.Rules[i] = *rule
			s.flags[rule.FeatureFlagID] = f
			return nil
		}
	}
	return repository.ErrFeatureFlagRuleNotFound
}

func (s *stubFeatureFlagRepo) DeleteRule(flagID, ruleID uint) error {
	f, ok := s.flags[flagID]
	if !ok {
		return repository.ErrFeatureFlagNotFound
	}
	for i := range f.Rules {
		if f.Rules[i].ID == ruleID {
			f.Rules = append(f.Rules[:i], f.Rules[i+1:]...)
			s.flags[flagID] = f
			return nil
		}
	}
	return repository.ErrFeatureFlagRuleNotFound
}

func nextFeatureFlagID(flags map[uint]domain.FeatureFlag) uint {
	var maxID uint
	for id := range flags {
		if id > maxID {
			maxID = id
		}
	}
	return maxID + 1
}

func nextFeatureFlagRuleID(rules []domain.FeatureFlagRule) uint {
	var maxID uint
	for _, rule := range rules {
		if rule.ID > maxID {
			maxID = rule.ID
		}
	}
	return maxID + 1
}

func TestFeatureFlagServiceEvaluatePrecedence(t *testing.T) {
	repo := &stubFeatureFlagRepo{flags: map[uint]domain.FeatureFlag{
		1: {
			ID:      1,
			Key:     "new_checkout",
			Enabled: false,
			Rules: []domain.FeatureFlagRule{
				{ID: 1, FeatureFlagID: 1, Type: FeatureFlagRuleTypePercent, Percentage: 100, Enabled: false, Priority: 50},
				{ID: 2, FeatureFlagID: 1, Type: FeatureFlagRuleTypeEnvironment, MatchValue: "prod", Enabled: false, Priority: 40},
				{ID: 3, FeatureFlagID: 1, Type: FeatureFlagRuleTypeRole, MatchValue: "admin", Enabled: true, Priority: 30},
				{ID: 4, FeatureFlagID: 1, Type: FeatureFlagRuleTypeUser, MatchValue: "42", Enabled: false, Priority: 20},
			},
		},
	}}
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
	repo := &stubFeatureFlagRepo{flags: map[uint]domain.FeatureFlag{1: {ID: 1, Key: "k"}}}
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
