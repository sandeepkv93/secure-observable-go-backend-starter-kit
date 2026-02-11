# Test Catalog

Generated from repository test sources (`*_test.go`) and test function declarations (`Test*`, `Benchmark*`, `Fuzz*`).

## Summary

- Total test files: 72
- Unit test files: 53
- Integration test files: 19
- Total test functions: 225
- Unit test functions: 176
- Integration test functions: 49

## Unit Tests

- `internal/config/config_profile_test.go`
  - `TestValidateTrustedActorBypassRequiresAllowlist`, `TestValidateTrustedActorBypassAcceptsCIDR`, `TestValidateRedisPoolSettings`, `TestValidateNonLocalRedisRequiresACLAndTLS`, `TestValidateRedisNamespacePattern`, `TestValidateIdempotencyDBCleanupSettings`, `TestValidateRateLimitRedisOutagePolicies`, `TestValidateProdProfileDisallowsFailOpenForSensitiveRateLimitScopes`, `TestValidateDevelopmentProfileAllowsRelaxedSettings`, `TestValidateProdProfileStrictRules`
- `internal/config/metrics_test.go`
  - `TestNormalizeConfigProfile`, `TestClassifyConfigLoadError`
- `internal/di/providers_test.go`
  - `TestRoutePolicyAdminWriteUsesSubjectKey`, `TestBuildRoutePolicyLimiterUsesFallbackKeyWhenEmpty`, `TestProvideGlobalRateLimiterUsesSubjectOrIP`, `TestRoutePoliciesNoRedisDoNotRequireContext`, `TestProvideHTTPServer`, `TestProvideForgotRateLimiterFallback`, `TestProvideForgotRateLimiterRedisFailClosed`, `TestProvideForgotRateLimiterRedisFailOpen`, `TestProvideGlobalRateLimiterRedisFailClosed`, `TestProvideRoutePolicyLoginRedisFailOpen`, `TestProvideRouterDependencies`, `TestProvideApp`, `TestStartDBIdempotencyCleanup`, `TestStartDBIdempotencyCleanupDisabledWhenRedisStoreUsed`, `TestProvideRedisClientEnabledForAdminListCache`, `TestProvideRouteRateLimitPolicies`, `TestProvideAuthAbuseGuard`, `TestProvideRequestBypassEvaluator`, `TestComposeRedisPrefix`, `TestRoutePolicyLoginLimiterEnforcesLimit`
- `internal/health/checker_test.go`
  - `TestProbeRunnerReady`, `TestProbeRunnerUnready`, `TestProbeRunnerStartupGrace`, `TestHealthOutcome`
- `internal/http/middleware/auth_middleware_test.go`
  - `TestAuthMiddlewareMissingTokenReturnsUnauthorized`, `TestAuthMiddlewareValidBearerTokenPasses`
- `internal/http/middleware/bypass_policy_test.go`
  - `TestNewRequestBypassEvaluatorIgnoresInvalidCIDRsAndCanReturnNil`, `TestRequestBypassEvaluatorMethodPathAndNilRequest`, `TestRequestBypassEvaluatorTrustedSubjectNormalizationAndFallback`
- `internal/http/middleware/idempotency_middleware_test.go`
  - `TestIdempotencyMiddlewareRejectsMissingAndTooLongKey`, `TestIdempotencyMiddlewareRejectsUnreadableBody`, `TestIdempotencyMiddlewareBeginErrorReturnsInternal`, `TestIdempotencyMiddlewareBeginStateBranches`, `TestIdempotencyMiddlewareCompleteBehavior`, `TestIdempotencyFingerprintUsesRoutePatternAndActorIdentity`
- `internal/http/middleware/rate_limit_middleware_test.go`
  - `TestDistributedRateLimiterAllowedSetsRateLimitHeaders`, `TestSubjectOrIPKeyFuncUsesSubjectWhenAccessTokenValid`, `TestSubjectOrIPKeyFuncFallsBackToIPWhenTokenInvalid`, `TestRateLimiterWithPolicyBurstThenSustained`, `TestRequestBypassEvaluatorProbePath`, `TestRequestBypassEvaluatorTrustedCIDR`, `TestRequestBypassEvaluatorTrustedSubject`, `TestRateLimiterBypassSkipsLimiter`, `TestRateLimitKeyType`, `TestDistributedRateLimiterFailOpenOnBackendError`, `TestDistributedRateLimiterFailClosedOnBackendError`, `TestDistributedRateLimiterDeniedSetsRetryAfter`
- `internal/http/middleware/rate_limit_redis_test.go`
  - `TestRedisFixedWindowLimiterAllowDenyAndFallbackKey`, `TestRedisFixedWindowLimiterBackendAndNilClientErrors`, `TestParseRedisInt64Branches`
- `internal/http/middleware/rbac_middleware_test.go`
  - `TestRequirePermissionDenied`, `TestRequirePermissionResolverError`, `TestRequirePermissionAllowed`
- `internal/http/middleware/request_logging_middleware_test.go`
  - `TestStructuredRequestLoggerInfoAndErrorLevels`, `TestStructuredRequestLoggerStatusFallbackTo200`
- `internal/http/middleware/security_middleware_test.go`
  - `TestCSRFMiddlewareRejectsMismatch`, `TestCORSAllowsKnownOrigin`, `TestCSRFMiddlewareAllowsMatchingToken`, `TestCSRFPathGroup`, `TestCORSRejectsUnknownOrigin`, `TestCORSPreflight`, `TestCSRFMiddlewareRejectsMissingCookie`, `TestBodyLimitAllowsSmallPayload`, `TestBodyLimitRejectsLargePayload`
- `internal/http/handler/admin_handler_test.go`
  - `TestAdminHandlerConditionalETag304`, `TestAdminHandlerNegativeLookupStaleFalsePositiveRoleUpdate`, `TestAdminHandlerMutationCacheInvalidation`, `TestAdminHandlerLockoutHelpersAndListParserFailures`
- `internal/http/handler/auth_handler_test.go`
  - `TestAuthHandlerLocalChangePasswordBranchesAndCookieSideEffects`, `TestAuthHandlerBypassAndLocalFlowErrorMappings`, `TestAuthHandlerRefreshAndLogoutCookieSideEffects`
- `internal/http/handler/user_handler_test.go`
  - `TestUserHandlerMeErrorMapping`, `TestUserHandlerSessionsResolveFallbackAndErrors`, `TestUserHandlerRevokeSessionMatrix`, `TestUserHandlerRevokeOtherSessionsMatrix`, `TestAuthUserIDAndClaimsParseError`, `TestSessionViewJSONShapeSmoke`
- `internal/http/response/response_test.go`
  - `TestError_DefaultEnvelopeWhenProblemNotRequested`, `TestError_ProblemDetailsWhenRequested`, `TestError_ContentNegotiationVariants`, `TestError_StatusTypeCodeConsistencyForKeyStatuses`
- `internal/http/router/router_test.go`
  - `TestRouterHealthReadyNilAndUnreadyBranches`, `TestRouterHealthLiveAlwaysOKWithDefaultLimiter`, `TestRouterFallbackGlobalRateLimiterWhenCustomNil`, `TestRouterRoutePolicyOverridesPerNamedPolicy`, `TestRouterCSRFScopeOnSensitiveRoutes`
- `internal/observability/audit_test.go`
  - `TestAuditEventValidateRejectsMissingEventName`, `TestBuildAuditEventIncludesRequiredFields`
- `internal/observability/logging_test.go`
  - `TestParseLogLevel`, `TestMultiHandlerEnabledAndHandle`, `TestTraceContextHandlerAddsTraceFields`
- `internal/observability/metrics_test.go`
  - `TestRecordMetricHelpersNoPanicWhenUninitialized`, `TestRecordMetricHelpersEmitExpectedLabelCardinality`, `TestInitMetricsDisabledReturnsProvider`
- `internal/observability/redis_metrics_test.go`
  - `TestClassifyKeyspaceOutcomeGet`, `TestClassifyKeyspaceOutcomeMGet`, `TestClassifyRedisError`, `TestClampRatio`
- `internal/observability/runtime_test.go`
  - `TestRuntimeShutdownNilAndEmpty`, `TestInitRuntimeAllDisabled`, `TestInitRuntimeMetricsErrorBranch`, `TestInitRuntimeTracingErrorBranch`
- `internal/observability/tracing_test.go`
  - `TestInitTracingDisabledBranch`, `TestInitTracingExporterErrorBranch`
- `internal/repository/local_credential_repository_test.go`
  - `TestLocalCredentialRepositoryFindByEmailJoinAndUpdates`
- `internal/repository/oauth_repository_test.go`
  - `TestOAuthRepositoryCreateFindAndUniqueness`
- `internal/repository/pagination_test.go`
  - `TestNormalizePageRequestBounds`, `TestCalcTotalPages`
- `internal/repository/permission_repository_test.go`
  - `TestPermissionRepositoryListPagedFindByPairsAndConflicts`
- `internal/repository/role_repository_test.go`
  - `TestRoleRepositoryCreateUpdateDeleteAndConflict`
- `internal/repository/session_repository_test.go`
  - `TestSessionRepositoryListActiveByUserID`, `TestSessionRepositoryRevokeScopeByUser`
- `internal/repository/user_repository_test.go`
  - `TestUserRepositoryListPagedFiltersSortAndRoleAssociations`
- `internal/repository/verification_token_repository_test.go`
  - `TestVerificationTokenRepositoryInvalidateFindConsume`, `TestVerificationTokenRepositoryConsumeIdempotencyAndConcurrency`
- `internal/security/jwt_test.go`
  - `TestJWTAccessAndRefreshParsing`
- `internal/security/cookie_test.go`
  - `TestNewCookieManagerSameSiteMapping`, `TestCookieManagerSetTokenCookiesFlagsAndPaths`, `TestCookieManagerClearTokenCookies`, `TestGetCookie`
- `internal/security/password_test.go`
  - `TestHashAndVerifyPassword`
- `internal/security/state_test.go`
  - `TestStateSignAndVerify`
- `internal/service/admin_list_cache_test.go`
  - `TestInMemoryAdminListCacheStoreExpiry`, `TestNoopAdminListCacheStoreAlwaysMisses`, `TestInMemoryAdminListCacheStoreGetSetInvalidate`
- `internal/service/admin_list_cache_redis_test.go`
  - `TestRedisAdminListCacheStoreNamespaceIndexAndInvalidateIdempotency`, `TestRedisAdminListCacheStoreGetWithAgeMetaFallbacks`
- `internal/service/auth_abuse_guard_test.go`
  - `TestInMemoryAuthAbuseGuardResetClearsCooldown`, `TestInMemoryAuthAbuseGuardDimensionIsolation`, `TestInMemoryAuthAbuseGuardExponentialCooldown`
- `internal/service/auth_abuse_guard_redis_test.go`
  - `TestRedisAuthAbuseGuardCooldownGrowthResetAndIsolation`, `TestRedisAuthAbuseGuardMalformedRedisValue`
- `internal/service/auth_password_policy_test.go`
  - `TestValidatePasswordPolicy`
- `internal/service/auth_service_test.go`
  - `TestAuthServiceRegisterLocalMatrix`, `TestAuthServiceLoginWithLocalPasswordMatrix`, `TestAuthServiceRequestAndConfirmEmailVerificationMatrix`, `TestAuthServiceForgotAndResetPasswordMatrix`, `TestAuthServiceChangeLocalPasswordMatrix`, `TestAuthServiceGoogleAndParseUserID`, `TestAuthServiceAssignBootstrapAdminIfNeededEdgeCases`
- `internal/service/idempotency_store_db_test.go`
  - `TestDBIdempotencyStoreCleanupExpiredDeletesOnlyExpiredRows`, `TestDBIdempotencyStoreCleanupExpiredHonorsBatchSize`
- `internal/service/idempotency_store_redis_test.go`
  - `TestRedisIdempotencyStoreStateTransitionsAndTTLRefresh`, `TestRedisIdempotencyStoreMalformedReplayPayloads`
- `internal/service/negative_lookup_cache_test.go`
  - `TestInMemoryNegativeLookupCacheStoreExpiry`, `TestNoopNegativeLookupCacheStoreAlwaysMisses`, `TestInMemoryNegativeLookupCacheStoreGetSetInvalidate`
- `internal/service/negative_lookup_cache_redis_test.go`
  - `TestRedisNegativeLookupCacheStoreSetGetInvalidateAndStale`
- `internal/service/oauth_service_test.go`
  - `TestOAuthServiceHandleGoogleCallbackExchangeError`, `TestOAuthServiceHandleGoogleCallbackUserInfoError`, `TestOAuthServiceHandleGoogleCallbackEmailNotVerified`, `TestClassifyOAuthError`
- `internal/service/rbac_permission_resolver_test.go`
  - `TestCachedPermissionResolverSingleflightDedupesConcurrentMisses`, `TestCachedPermissionResolverCachesBySession`, `TestCachedPermissionResolverInvalidateUser`
- `internal/service/rbac_permission_cache_store_redis_test.go`
  - `TestRedisRBACPermissionCacheStoreKeyingAndInvalidation`, `TestRedisRBACPermissionCacheStoreMalformedEpochValue`
- `internal/service/rbac_service_test.go`
  - `TestRBACPermissionEvaluation`
- `internal/service/token_service_test.go`
  - `TestTokenRotateSuccessPreservesFamily`, `TestTokenRotateReuseRevokesFamily`, `TestTokenRotateInvalidDoesNotRevokeActiveSessions`, `TestTokenRotateBackfillsLegacyLineage`
- `internal/tools/loadgen/run_test.go`
  - `TestNormalizeProfile`, `TestClassifyStatusClass`

## Integration Tests

- `test/integration/admin_list_cache_test.go`
  - `TestAdminListRolesSingleflightDedupesConcurrentMisses`, `TestAdminListConditionalETagForRolesAndPermissions`, `TestAdminListRolesReadThroughCacheAndInvalidation`
- `test/integration/admin_list_pagination_test.go`
  - `TestAdminListRolesAndPermissionsPaginationFilterSort`, `TestAdminListInvalidSortByRejected`, `TestAdminListUsersPaginationFilterSort`
- `test/integration/admin_rbac_write_test.go`
  - `TestAdminRBACProtectedRoleDeletionRejected`, `TestAdminRBACPermissionConflict`, `TestAdminRBACSyncIdempotent`
- `test/integration/admin_rbac_mutation_matrix_test.go`
  - `TestAdminRoleUpdateMutationMatrix`, `TestAdminPermissionMutationMatrix`, `TestAdminSetUserRolesValidationAndServiceError`
- `test/integration/audit_taxonomy_test.go`
  - `TestAuditTaxonomySchemaAndKeyEndpointEvents`
- `test/integration/auth_abuse_test.go`
  - `TestLocalLoginAbuseCooldownBlocksRapidRetries`, `TestLocalLoginAbuseBypassForTrustedCIDR`, `TestPasswordForgotAbuseCooldownUsesIdentityAndIP`
- `test/integration/auth_google_oauth_test.go`
  - `TestGoogleLoginRedirectAndDisabled`, `TestGoogleCallbackValidationErrors`, `TestGoogleCallbackSuccessSetsCookiesAndClearsState`, `TestGoogleCallbackDisabledAndProviderErrors`
- `test/integration/auth_lifecycle_test.go`
  - `TestAuthLifecycleCSRFMiddleware`, `TestAuthLifecycleRefreshReuseInvalidatesFamily`, `TestAuthLifecycleLoginRefreshLogoutRevoked`
- `test/integration/auth_middleware_test.go`
  - `TestProtectedRouteRequiresToken`
- `test/integration/email_verification_test.go`
  - `TestEmailVerificationReuseAndInvalidTokenFailUniformly`, `TestEmailVerificationRegisterRequestConfirmAndLogin`, `TestEmailVerificationRequestUnknownEmailReturnsAccepted`, `TestEmailVerificationExpiredTokenFails`
- `test/integration/health_endpoints_test.go`
  - `TestHealthLiveAndReadyEndpoints`
- `test/integration/idempotency_test.go`
  - `TestIdempotencyRegisterReplayAndConflict`, `TestIdempotencyMissingKeyRejectedOnScopedEndpoint`, `TestIdempotencyAdminRoleCreateReplay`
- `test/integration/password_reset_test.go`
  - `TestPasswordResetHappyPathRevokesSessions`, `TestPasswordResetReplayAndUnknownForgotResponse`, `TestPasswordResetReuseAndExpiredFail`
- `test/integration/problem_details_test.go`
  - `TestProblemDetailsContentNegotiation_DefaultEnvelope`, `TestProblemDetailsContentNegotiation_ProblemJSON`, `TestProblemDetailsConsistencyFor400401403404`
- `test/integration/rate_limit_test.go`
  - `TestRoutePolicyMapLoginAndRefreshLimits`, `TestRoutePolicyMapAdminWriteAndSyncLimits`, `TestRateLimiterBlocksAfterLimit`, `TestRateLimiterSubjectKeyingAcrossIPs`
- `test/integration/rbac_forbidden_test.go`
  - `TestRBACForbiddenWithoutPermission`
- `test/integration/rbac_permission_cache_test.go`
  - `TestRBACPermissionCacheEnforcesRoleChangeWithoutRelogin`
- `test/integration/redis_race_integration_test.go`
  - `TestRedisRateLimiterConcurrentBurstHonorsLimit`, `TestRedisIdempotencyConcurrentInProgressAndReplayConsistency`
- `test/integration/session_management_test.go`
  - `TestSessionManagementRevokeErrors`, `TestSessionManagementListAndRevokeByDevice`, `TestSessionManagementRevokeOthersKeepsCurrent`

## Bazel go_test Targets

- `internal/http/middleware/BUILD.bazel`: name = "middleware_test",
- `internal/http/handler/BUILD.bazel`: name = "handler_test",
- `internal/http/response/BUILD.bazel`: name = "response_test",
- `internal/http/router/BUILD.bazel`: name = "router_test",
- `internal/health/BUILD.bazel`: name = "health_test",
- `internal/repository/BUILD.bazel`: name = "repository_test",
- `internal/config/BUILD.bazel`: name = "config_test",
- `internal/di/BUILD.bazel`: name = "di_test",
- `internal/security/BUILD.bazel`: name = "security_test",
- `internal/observability/BUILD.bazel`: name = "observability_test",
- `internal/tools/loadgen/BUILD.bazel`: name = "loadgen_test",
- `internal/service/BUILD.bazel`: name = "service_test",
- `test/integration/BUILD.bazel`: name = "integration_test",

## Notes

- Integration tests under `test/integration/` include API-level and Redis-container race/replay scenarios.
- This catalog lists declared test functions; subtests created via `t.Run(...)` are part of their parent test function.
