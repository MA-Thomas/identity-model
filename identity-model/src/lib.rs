//! Identity domain facts and verified workflow entry points.
//!
pub mod authority;
pub mod clock;
pub mod continuity;
pub mod device;
pub mod fen;
pub mod flows;
pub mod iam;
pub mod identity;
pub mod identity_proofing;
pub mod ids;
pub mod liveness;
pub mod login;
pub mod materialized;
pub mod narrative;
pub mod persistence;
pub mod policy;
pub mod provider;
pub mod service;
pub mod time;
pub mod translation;
pub mod workflows;

pub use clock::{Clock, FixedClock};
pub use continuity::{
    canonical_continuity_assertion_bytes, deterministic_signature_for_test,
    verify_signed_continuity_assertion, ChallengeId, ContinuityAssertion,
    ContinuityAssertionRejectionReason, ContinuityAssertionVerificationResult,
    ContinuityAssuranceMapper, ContinuityChallenge, ContinuityProviderMetadata,
    ContinuitySignatureVerifier, ExpectedSignatureVerifier, InMemoryNonceLifecycle, Nonce,
    NonceStatus, RegistryBackedSignatureVerifier, ResultBasedAssuranceMapper, Signature,
    SignedContinuityAssertion, TrackedContinuityChallenge, VerificationKey, VerificationKeyId,
    VerificationKeyRegistry, VerificationKeyStatus, CONTINUITY_ASSERTION_PROFILE_NAME,
    CONTINUITY_ASSERTION_PROFILE_VERSION,
};
pub use device::{
    validate_app_attest_assertion_context, validate_app_attest_key_registration,
    validate_app_attest_request_config, AppAttestAssertionVerificationError,
    AppAttestAssertionVerificationRequest, AppAttestAssertionVerifier, AppAttestClientConfig,
    AppAttestEnvironment, AppAttestKeyRegistration, AppAttestKeyRegistrationStore,
    AppAttestKeyState, AppAttestKeyStateStatus, AppAttestKeyStateStore,
    InMemoryAppAttestKeyStateStore, StatefulAppAttestAssertionVerifier,
    StaticAppAttestAssertionVerifier, VerifiedAppAttestAssertion,
};
pub use fen::{
    compare_timestamps, seconds_between, timestamp_after, timestamp_at_or_after, timestamp_before,
    timestamp_in_closed_interval, timestamp_to_unix_seconds, unix_seconds_to_timestamp, Author,
    AuthorId, AuthorType, AuthorizationBasis, CodedValue, CodingSystem, ContentHash, Date,
    DecisionPointId, DeviceRef, DocumentId, DocumentRef, ExternalRef, ExternalSystem, Fact, FactId,
    FactPayload, FactStatus, MembershipId, NarrativeId, OrganizationRef, PolicyRef,
    ProblemEpisodeId, Provenance, ProvenanceTier, RelationId, SectionId, SubjectId,
    SupersessionReason, TemporalAnchor, TimeInterval, Timestamp, TimestampParseError, UtcTimestamp,
};
pub use flows::{
    access_authorization_episode, account_recovery_episode, bind_device_slice_from_request,
    complete_record_export_step_up_outcome_from_request,
    complete_record_export_step_up_slice_from_request, contested_provider_link_resolution_slice,
    delegation_episode, dispute_resolution_episode, duplicate_subject_merge_slice,
    enroll_continuity_slice_from_request, episode_membership, episode_relation,
    identity_dispute_resolution_slice_from_request, identity_verification_episode,
    incorrect_merge_split_slice, link_payer_identity_slice_from_request,
    link_provider_identity_slice_from_request, onboarding_identity_witnesses_slice_from_request,
    parent_onboarding_episode, register_subject_slice_from_request, witness_supersession_slice,
    AccountSessionBootstrapRequest, BindDeviceRequest, CompleteRecordExportStepUpOutcome,
    CompleteRecordExportStepUpRequest, EnrollContinuityRequest, IdentityDisputeResolutionKind,
    IdentityDisputeResolutionRequest, IdentityWorkflowSlice, LinkPayerIdentityRequest,
    LinkProviderIdentityRequest, OnboardingIdentityWitnessesRequest, RegisterNewSubjectRequest,
    RegisterSubjectRequest, VerticalSliceError, WorkflowIdPlan,
};
pub use iam::{
    validate_oidc_session_context, OidcAssurancePolicy, OidcClientConfig, OidcCredentialEvidence,
    OidcSessionVerificationError, OidcSessionVerifier, StaticOidcSessionVerifier,
    VerifiedOidcSession,
};
pub use identity::{
    AccessDecisionResult, AssuranceLevel, AuthenticatorType, AuthorityScope, AuthorityType,
    AuthorizedAction, BiometricModality, ContinuityCheckResult,
    ContinuityVerificationRejectionReason, CredentialAssertionResult, DisputeResolutionOutcome,
    IdentityAttribute, IdentityAttributeValue, IdentityWitnessContext, IdentityWitnessResult,
    IdentityWitnessType, MatchConfidence, ParticipationRole, PresentationAttackDetectionResult,
    RecoveryMethod, RecoveryResult, RiskEvaluationResult, SensitiveAction, StableIdentityProfile,
    Subject, SubjectGraphCorrectionReason, SubjectKind, SubjectStatus, SubjectSupersessionReason,
};
pub use identity_proofing::{
    IdentityProofingAssertedAttribute, IdentityProofingEvidenceType, IdentityProofingProvider,
    IdentityProofingRiskSignal, IdentityProofingVerificationError,
    IdentityProofingVerificationRequest, PersonaIdentityProofingProvider,
    StaticIdentityProofingProvider, VerifiedIdentityProofingEvidence, PERSONA_PROVIDER_NAME,
};
pub use ids::{DeterministicIdGenerator, IdGenerator};
pub use liveness::{
    terminal_live_presence_challenge_status_for_ceremony, validate_live_presence_challenge_context,
    validate_liveness_bound_to_app_attest, validate_liveness_ceremony_context,
    validate_liveness_provider_callback_request, InMemoryLivePresenceChallengeStore,
    LivePresenceChallenge, LivePresenceChallengeError, LivePresenceChallengeFailureReason,
    LivePresenceChallengeId, LivePresenceChallengeManualReviewReason, LivePresenceChallengeStatus,
    LivePresenceChallengeStore, LivePresenceChallengeWorkflow, LivePresenceExpectedAppContext,
    LivenessCeremonyVerificationError, LivenessCeremonyVerificationRequest,
    LivenessCeremonyVerifier, LivenessProviderCallbackVerificationError,
    LivenessProviderCallbackVerificationRequest, LivenessProviderCallbackVerifier,
    StaticLivenessCeremonyVerifier, StaticLivenessProviderCallbackVerifier,
    VerifiedLivenessCeremony,
};
pub use materialized::{
    authorization_snapshot, project_identity_history, AccessDecisionView,
    AuthorityRelationshipView, AuthorizationSnapshot, ClinicalIdentityLinkView, IdentityHistory,
    PayerIdentityLinkView, ProjectionError,
};
pub use narrative::workflow_narrative_lines;
pub use persistence::{
    build_stored_encrypted_episode_composition, build_stored_encrypted_workflow_slice,
    canonical_encrypted_fact_associated_data, canonical_encrypted_fact_associated_data_in_family,
    encrypt_fact_envelope, encrypt_fact_envelope_in_family, materialize_encrypted_fact,
    materialize_encrypted_fact_in_family, materialize_encrypted_fact_with_audit,
    materialize_encrypted_fact_with_audit_in_family, materialize_encrypted_facts,
    materialize_encrypted_facts_in_family, replay_identity_state,
    replay_identity_state_from_repository, replay_identity_state_from_repository_at,
    Aes256GcmFactEncryptionMetadataPlanner, AppendOnlyEpisodeRelationRepository,
    AppendOnlyEpisodeRepository, AppendOnlyFactRepository, AppendOnlyMembershipRepository,
    AppendSequence, DeterministicTestFactEncryptionMetadataPlanner, DeterministicTestFactEncryptor,
    EncryptedEpisodeCompositionAppendSequencePlan, EncryptedFactAssociatedDataVersion,
    EncryptedFactPlaintext, EncryptedFactPlaintextCodec, EncryptedFactPlaintextOf,
    EncryptedFactRepository, EncryptedFactStoreError, EncryptedWorkflowAppendSequencePlan,
    EncryptedWorkflowAppendSequenceState, EncryptionAwareWorkflowRepository,
    EncryptionAwareWorkflowRepositoryError, FactDataEncryptionKey, FactEncryptionAlgorithm,
    FactEncryptionError, FactEncryptionKeyId, FactEncryptionMetadata,
    FactEncryptionMetadataPlanner, FactKeyAccessError, FactKeyResolver, FactKeyStatus,
    FactMaterializationAuditContext, FactMaterializationAuditEvent,
    FactMaterializationAuditOutcome, FactMaterializationAuditSink, FactMaterializationError,
    FactPayloadEncryptor, FactPayloadType, IdentityEncryptedFactPlaintextExt,
    IdentityPayloadFamily, IdentityWorkflowRepository, InMemoryEncryptedEnvelopeStore,
    InMemoryEncryptedFactEnvelopeRepository, InMemoryEncryptedFactPlaintextCodec,
    InMemoryEncryptedFactRepository, InMemoryFactMaterializationAuditLog,
    InMemoryIdentityRepository, InMemoryStoredEncryptedWorkflowRepository,
    MaterializationAuthorization, MaterializationAuthorizationDecision,
    NoopFactMaterializationAuditSink, PayloadFamily, PersistenceTransactionId, RepositoryError,
    StaticFactKeyResolver, StoredEncryptedFact, StoredEncryptedFactEnvelope,
    StoredEncryptedWorkflowRepository, StoredEpisodeComposition, StoredEpisodeMembership,
    StoredEpisodeRelation, StoredIdentityWorkflowSlice, StoredProblemEpisode,
    ENCRYPTED_FACT_AAD_PROFILE_NAME, ENCRYPTED_FACT_AAD_PROFILE_VERSION_V1,
};
pub use policy::{
    default_policy_for_action, evaluate_action_policy_with_context,
    evaluate_policy_artifact_with_context, versioned_policy_ref, ActionPolicy,
    BreakGlassPolicyDefinition, DelegationConstraintsPolicyDefinition,
    EmergencyAccessPolicyDefinition, EvidenceFreshnessRequirements, EvidenceSummary,
    FreshnessRequirement, PolicyArtifact, PolicyArtifactDefinition, PolicyArtifactStatus,
    PolicyEvaluation, PolicyEvaluationContext, PolicyEvaluationReason, PolicyReview,
    RecoveryMethodChangePolicyDefinition, SensitiveActionPolicyDefinition,
};
pub use provider::{
    ContinuityEnrollment, ContinuityEnrollmentRequest, ContinuityProviderCapabilities,
    ContinuityProviderError, ContinuityVaultProvider, MockHostedContinuityProvider,
    MockPhase1ContinuityProvider,
};
pub use service::{
    AccessAuthorizationOutcome, AccountSessionBootstrapOutcome, AccountTokenBootstrapError,
    AccountTokenBootstrapRequest, AccountTokenWithAppAttestBootstrapError,
    AccountTokenWithAppAttestBootstrapRequest, ContinuityAssertionVerificationAuditRequest,
    ContinuityAssertionVerificationOutcome, ContinuityChallengeRequest,
    ContinuityEnrollmentOutcome, CoreIdentityOnboardingOutcome, CoreIdentityOnboardingRequest,
    DeviceBindingOutcome, IdentityDisputeOutcome, IdentityWorkflowService,
    PayerIdentityLinkOutcome, ProviderIdentityLinkOutcome,
    RepositoryBackedAccountSessionBootstrapOutcome, RepositoryBackedCoreIdentityOnboardingOutcome,
    RepositoryBackedWorkflowOutcome, SensitiveActionEvaluationRequest,
    SensitiveActionPolicyArtifactEvaluationRequest, SubjectRegistrationOutcome, WorkflowOutcome,
};
pub use translation::{FactDraft, FenTranslator};
pub use workflows::{
    ApproximateDate, DatePrecision, EpisodeKind, EpisodeMembership, EpisodeRelation,
    EpisodeRelationStatus, EpisodeRelationType, EpisodeStatus, FactRole, MembershipStatus,
    ProblemEpisode, ResolutionInfo,
};

pub mod disclosure;
