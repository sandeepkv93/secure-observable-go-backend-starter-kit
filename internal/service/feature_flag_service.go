package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
)

const (
	FeatureFlagRuleTypeUser        = "user"
	FeatureFlagRuleTypeRole        = "role"
	FeatureFlagRuleTypeOrg         = "org"
	FeatureFlagRuleTypeEnvironment = "environment"
	FeatureFlagRuleTypePercent     = "percent"
)

var (
	ErrFeatureFlagInvalidRuleType  = errors.New("invalid feature flag rule type")
	ErrFeatureFlagInvalidRuleValue = errors.New("invalid feature flag rule value")
)

type FeatureFlagEvaluationContext struct {
	UserID      uint
	Roles       []string
	Org         string
	Environment string
}

type FeatureFlagEvaluationResult struct {
	Key         string `json:"key"`
	Enabled     bool   `json:"enabled"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

type featureFlagCachedPayload struct {
	Values []FeatureFlagEvaluationResult `json:"values"`
}

type DefaultFeatureFlagService struct {
	repo     repository.FeatureFlagRepository
	cache    FeatureFlagEvaluationCacheStore
	cacheTTL time.Duration
}

func NewFeatureFlagService(repo repository.FeatureFlagRepository, cache FeatureFlagEvaluationCacheStore) *DefaultFeatureFlagService {
	if cache == nil {
		cache = NewNoopFeatureFlagEvaluationCacheStore()
	}
	return &DefaultFeatureFlagService{repo: repo, cache: cache, cacheTTL: 30 * time.Second}
}

func (s *DefaultFeatureFlagService) EvaluateAll(ctx context.Context, evalCtx FeatureFlagEvaluationContext) ([]FeatureFlagEvaluationResult, error) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordFeatureFlagEvaluation(ctx, "all", status, time.Since(start))
	}()

	cacheKey := buildFeatureFlagCacheKey(evalCtx)
	if payload, ok := s.readCachedEvaluation(ctx, cacheKey); ok {
		observability.RecordFeatureFlagEvaluationCache(ctx, "hit")
		return payload.Values, nil
	}
	observability.RecordFeatureFlagEvaluationCache(ctx, "miss")

	flags, err := s.repo.ListFlags()
	if err != nil {
		status = "error"
		return nil, err
	}

	results := make([]FeatureFlagEvaluationResult, 0, len(flags))
	for _, flag := range flags {
		enabled, source := evaluateFeatureFlag(flag, evalCtx)
		results = append(results, FeatureFlagEvaluationResult{
			Key:         flag.Key,
			Enabled:     enabled,
			Source:      source,
			Description: flag.Description,
		})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Key < results[j].Key })
	_ = s.writeCachedEvaluation(ctx, cacheKey, featureFlagCachedPayload{Values: results})
	return results, nil
}

func (s *DefaultFeatureFlagService) EvaluateByKey(ctx context.Context, key string, evalCtx FeatureFlagEvaluationContext) (*FeatureFlagEvaluationResult, error) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordFeatureFlagEvaluation(ctx, "single", status, time.Since(start))
	}()

	flag, err := s.repo.FindFlagByKey(strings.TrimSpace(strings.ToLower(key)))
	if err != nil {
		status = "error"
		return nil, err
	}
	enabled, source := evaluateFeatureFlag(*flag, evalCtx)
	return &FeatureFlagEvaluationResult{
		Key:         flag.Key,
		Enabled:     enabled,
		Source:      source,
		Description: flag.Description,
	}, nil
}

func (s *DefaultFeatureFlagService) ListFlags(ctx context.Context) ([]domain.FeatureFlag, error) {
	return s.repo.ListFlags()
}

func (s *DefaultFeatureFlagService) GetFlagByID(ctx context.Context, id uint) (*domain.FeatureFlag, error) {
	return s.repo.FindFlagByID(id)
}

func (s *DefaultFeatureFlagService) CreateFlag(ctx context.Context, flag *domain.FeatureFlag) error {
	flag.Key = strings.TrimSpace(strings.ToLower(flag.Key))
	if flag.Key == "" {
		return ErrFeatureFlagInvalidRuleValue
	}
	if err := s.repo.CreateFlag(flag); err != nil {
		return err
	}
	return s.cache.InvalidateAll(ctx)
}

func (s *DefaultFeatureFlagService) UpdateFlag(ctx context.Context, flag *domain.FeatureFlag) error {
	flag.Key = strings.TrimSpace(strings.ToLower(flag.Key))
	if flag.Key == "" {
		return ErrFeatureFlagInvalidRuleValue
	}
	if err := s.repo.UpdateFlag(flag); err != nil {
		return err
	}
	return s.cache.InvalidateAll(ctx)
}

func (s *DefaultFeatureFlagService) DeleteFlag(ctx context.Context, id uint) error {
	if err := s.repo.DeleteFlag(id); err != nil {
		return err
	}
	return s.cache.InvalidateAll(ctx)
}

func (s *DefaultFeatureFlagService) ListRules(ctx context.Context, flagID uint) ([]domain.FeatureFlagRule, error) {
	return s.repo.ListRules(flagID)
}

func (s *DefaultFeatureFlagService) CreateRule(ctx context.Context, rule *domain.FeatureFlagRule) error {
	if err := normalizeAndValidateRule(rule); err != nil {
		return err
	}
	if err := s.repo.CreateRule(rule); err != nil {
		return err
	}
	return s.cache.InvalidateAll(ctx)
}

func (s *DefaultFeatureFlagService) UpdateRule(ctx context.Context, rule *domain.FeatureFlagRule) error {
	if err := normalizeAndValidateRule(rule); err != nil {
		return err
	}
	if err := s.repo.UpdateRule(rule); err != nil {
		return err
	}
	return s.cache.InvalidateAll(ctx)
}

func (s *DefaultFeatureFlagService) DeleteRule(ctx context.Context, flagID, ruleID uint) error {
	if err := s.repo.DeleteRule(flagID, ruleID); err != nil {
		return err
	}
	return s.cache.InvalidateAll(ctx)
}

func evaluateFeatureFlag(flag domain.FeatureFlag, ctx FeatureFlagEvaluationContext) (bool, string) {
	rules := append([]domain.FeatureFlagRule(nil), flag.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority < rules[j].Priority
	})

	if matched, value := evaluateRuleByType(rules, FeatureFlagRuleTypeUser, ctx); matched {
		return value, "rule:user"
	}
	if matched, value := evaluateRuleByType(rules, FeatureFlagRuleTypeRole, ctx); matched {
		return value, "rule:role"
	}
	if matched, value := evaluateRuleByType(rules, FeatureFlagRuleTypeOrg, ctx); matched {
		return value, "rule:org"
	}
	if matched, value := evaluateRuleByType(rules, FeatureFlagRuleTypeEnvironment, ctx); matched {
		return value, "rule:environment"
	}
	if matched, value := evaluateRuleByType(rules, FeatureFlagRuleTypePercent, ctx); matched {
		return value, "rule:percent"
	}
	return flag.Enabled, "default"
}

func evaluateRuleByType(rules []domain.FeatureFlagRule, ruleType string, ctx FeatureFlagEvaluationContext) (bool, bool) {
	for _, rule := range rules {
		if rule.Type != ruleType {
			continue
		}
		if matchesRule(rule, ctx) {
			return true, rule.Enabled
		}
	}
	return false, false
}

func matchesRule(rule domain.FeatureFlagRule, ctx FeatureFlagEvaluationContext) bool {
	switch rule.Type {
	case FeatureFlagRuleTypeUser:
		return rule.MatchValue == strconv.FormatUint(uint64(ctx.UserID), 10)
	case FeatureFlagRuleTypeRole:
		target := strings.ToLower(strings.TrimSpace(rule.MatchValue))
		for _, role := range ctx.Roles {
			if strings.ToLower(strings.TrimSpace(role)) == target {
				return true
			}
		}
		return false
	case FeatureFlagRuleTypeOrg:
		return strings.EqualFold(strings.TrimSpace(rule.MatchValue), strings.TrimSpace(ctx.Org))
	case FeatureFlagRuleTypeEnvironment:
		return strings.EqualFold(strings.TrimSpace(rule.MatchValue), strings.TrimSpace(ctx.Environment))
	case FeatureFlagRuleTypePercent:
		if rule.Percentage <= 0 || ctx.UserID == 0 {
			return false
		}
		if rule.Percentage >= 100 {
			return true
		}
		bucket := stablePercentBucket(rule.FeatureFlagID, ctx.UserID)
		return bucket < rule.Percentage
	default:
		return false
	}
}

func stablePercentBucket(flagID, userID uint) int {
	src := fmt.Sprintf("%d:%d", flagID, userID)
	sum := sha256.Sum256([]byte(src))
	const bucketCount uint16 = 100
	const maxUint16 = ^uint16(0)
	// Rejection sampling removes modulo bias while keeping conversion ranges small and safe.
	// 65536 mod 100 = 36, so we accept only values below 65500.
	limit := maxUint16 - (maxUint16 % bucketCount)
	for i := 0; i+2 <= len(sum); i += 2 {
		candidate := binary.BigEndian.Uint16(sum[i : i+2])
		if candidate < limit {
			return int(candidate % bucketCount)
		}
	}
	return int(binary.BigEndian.Uint16(sum[:2]) % bucketCount)
}

func normalizeAndValidateRule(rule *domain.FeatureFlagRule) error {
	rule.Type = strings.TrimSpace(strings.ToLower(rule.Type))
	rule.MatchValue = strings.TrimSpace(strings.ToLower(rule.MatchValue))
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	switch rule.Type {
	case FeatureFlagRuleTypeUser, FeatureFlagRuleTypeRole, FeatureFlagRuleTypeOrg, FeatureFlagRuleTypeEnvironment:
		if rule.MatchValue == "" {
			return ErrFeatureFlagInvalidRuleValue
		}
		rule.Percentage = 0
	case FeatureFlagRuleTypePercent:
		if rule.Percentage < 0 || rule.Percentage > 100 {
			return ErrFeatureFlagInvalidRuleValue
		}
		rule.MatchValue = ""
	default:
		return ErrFeatureFlagInvalidRuleType
	}
	return nil
}

func buildFeatureFlagCacheKey(evalCtx FeatureFlagEvaluationContext) string {
	normalizedRoles := append([]string(nil), evalCtx.Roles...)
	for i := range normalizedRoles {
		normalizedRoles[i] = strings.TrimSpace(strings.ToLower(normalizedRoles[i]))
	}
	sort.Strings(normalizedRoles)
	return fmt.Sprintf("u:%d|roles:%s|org:%s|env:%s", evalCtx.UserID, strings.Join(normalizedRoles, ","), strings.TrimSpace(strings.ToLower(evalCtx.Org)), strings.TrimSpace(strings.ToLower(evalCtx.Environment)))
}

func (s *DefaultFeatureFlagService) readCachedEvaluation(ctx context.Context, key string) (featureFlagCachedPayload, bool) {
	if s.cache == nil {
		return featureFlagCachedPayload{}, false
	}
	raw, ok, err := s.cache.Get(ctx, key)
	if err != nil || !ok {
		return featureFlagCachedPayload{}, false
	}
	var payload featureFlagCachedPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return featureFlagCachedPayload{}, false
	}
	return payload, true
}

func (s *DefaultFeatureFlagService) writeCachedEvaluation(ctx context.Context, key string, payload featureFlagCachedPayload) error {
	if s.cache == nil {
		return nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.cache.Set(ctx, key, encoded, s.cacheTTL)
}
