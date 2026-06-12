use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterSubjectRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub subject_kind: SubjectKind,
    pub stable_profile: StableIdentityProfile,
}

impl RegisterSubjectRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
        subject_kind: SubjectKind,
        stable_profile: StableIdentityProfile,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, 1),
            subject_kind,
            stable_profile,
        }
    }

    pub fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "register-subject",
                ProblemEpisodeId("episode-register-subject".to_string()),
                1,
            ),
            subject_kind: SubjectKind::HumanPerson,
            stable_profile: StableIdentityProfile {
                legal_name: Some("Example Patient".to_string()),
                date_of_birth: Some(Date("1990-01-01".to_string())),
                demographic_attributes: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterNewSubjectRequest {
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub subject_id_prefix: String,
    pub id_namespace: String,
    pub subject_kind: SubjectKind,
    pub stable_profile: StableIdentityProfile,
}

impl RegisterNewSubjectRequest {
    pub fn new(
        authored_by: Author,
        started_at: Timestamp,
        subject_id_prefix: impl Into<String>,
        id_namespace: impl Into<String>,
        subject_kind: SubjectKind,
        stable_profile: StableIdentityProfile,
    ) -> Self {
        Self {
            authored_by,
            started_at,
            subject_id_prefix: subject_id_prefix.into(),
            id_namespace: id_namespace.into(),
            subject_kind,
            stable_profile,
        }
    }

    pub fn fixture(authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            authored_by,
            started_at,
            subject_id_prefix: "subject".to_string(),
            id_namespace: "register-subject".to_string(),
            subject_kind: SubjectKind::HumanPerson,
            stable_profile: StableIdentityProfile {
                legal_name: Some("Example Patient".to_string()),
                date_of_birth: Some(Date("1990-01-01".to_string())),
                demographic_attributes: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDeviceRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub device_ref: DeviceRef,
    pub authenticator_type: AuthenticatorType,
    pub assurance_level: AssuranceLevel,
    pub source_system: Option<String>,
}

impl BindDeviceRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
        device_ref: DeviceRef,
        authenticator_type: AuthenticatorType,
        assurance_level: AssuranceLevel,
        source_system: Option<String>,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, 1),
            device_ref,
            authenticator_type,
            assurance_level,
            source_system,
        }
    }

    pub fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "bind-device",
                ProblemEpisodeId("episode-bind-device".to_string()),
                1,
            ),
            device_ref: "device-passkey-1".to_string(),
            authenticator_type: AuthenticatorType::Passkey,
            assurance_level: AssuranceLevel::Medium,
            source_system: Some("AccountBootstrap".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollContinuityRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub modality: BiometricModality,
}

impl EnrollContinuityRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
        modality: BiometricModality,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, 1),
            modality,
        }
    }

    pub fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "enroll-continuity",
                ProblemEpisodeId("episode-enroll-continuity".to_string()),
                1,
            ),
            modality: BiometricModality::Face,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernmentIdWitnessInput {
    pub source_system: Option<String>,
    pub provider_event_id: Option<String>,
    pub evidence_ref: Option<DocumentRef>,
    pub assurance_level: AssuranceLevel,
    pub expires_at: Option<Timestamp>,
    pub retention_policy_refs: Vec<PolicyRef>,
}

impl GovernmentIdWitnessInput {
    pub fn external_refs(&self) -> Vec<ExternalRef> {
        self.provider_event_id
            .as_ref()
            .map(|provider_event_id| {
                vec![ExternalRef {
                    system: ExternalSystem::Other(
                        self.source_system
                            .clone()
                            .unwrap_or_else(|| "IdentityProofingProvider".to_string()),
                    ),
                    resource_type: Some("government_id_verification_event".to_string()),
                    resource_id: provider_event_id.clone(),
                    uri: None,
                }]
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingIdentityWitnessesRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub identity_proofing: VerifiedIdentityProofingEvidence,
    pub liveness: VerifiedLivenessCeremony,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkProviderIdentityRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub provider_org: OrganizationRef,
    pub external_patient_ref: ExternalRef,
    pub match_confidence: MatchConfidence,
    pub source_system: Option<String>,
}

impl LinkProviderIdentityRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
        provider_org: OrganizationRef,
        external_patient_ref: ExternalRef,
        match_confidence: MatchConfidence,
        source_system: Option<String>,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, 1),
            provider_org,
            external_patient_ref,
            match_confidence,
            source_system,
        }
    }

    pub fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "link-provider",
                ProblemEpisodeId("episode-link-provider".to_string()),
                1,
            ),
            provider_org: "Example Health".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-123".to_string(),
                uri: None,
            },
            match_confidence: MatchConfidence::High,
            source_system: Some("FHIRLinker".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPayerIdentityRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub payer: String,
    pub member_ref: String,
    pub effective_period: Option<TimeInterval>,
    pub source_system: Option<String>,
}

impl LinkPayerIdentityRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
        payer: String,
        member_ref: String,
        effective_period: Option<TimeInterval>,
        source_system: Option<String>,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, 1),
            payer,
            member_ref,
            effective_period,
            source_system,
        }
    }

    pub fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "link-payer",
                ProblemEpisodeId("episode-link-payer".to_string()),
                1,
            ),
            payer: "Example Payer".to_string(),
            member_ref: "member-123".to_string(),
            effective_period: None,
            source_system: Some("PayerLinker".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub stable_profile: StableIdentityProfile,
    pub modality: BiometricModality,
    pub device_ref: DeviceRef,
    pub provider_org: OrganizationRef,
    pub external_patient_ref: ExternalRef,
    pub payer: String,
    pub member_ref: String,
}

impl OnboardingRequest {
    pub fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "onboarding",
                ProblemEpisodeId("episode-onboarding".to_string()),
                6,
            ),
            stable_profile: StableIdentityProfile {
                legal_name: Some("Example Patient".to_string()),
                date_of_birth: Some(Date("1990-01-01".to_string())),
                demographic_attributes: Vec::new(),
            },
            modality: BiometricModality::Face,
            device_ref: "device-passkey-1".to_string(),
            provider_org: "Example Health".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-123".to_string(),
                uri: None,
            },
            payer: "Example Payer".to_string(),
            member_ref: "member-123".to_string(),
        }
    }
}

pub fn register_subject_slice_from_request(
    request: RegisterSubjectRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );
    let drafts = vec![translator.subject_created(
        request.subject_id.clone(),
        request.subject_kind,
        request.stable_profile,
        request.started_at.clone(),
    )];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![FactRole::IdentityAnchor],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

pub fn bind_device_slice_from_request(
    request: BindDeviceRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );
    let drafts = vec![translator.device_binding_established(
        request.subject_id.clone(),
        request.started_at.clone(),
        request.device_ref,
        request.authenticator_type,
        request.assurance_level,
        request.source_system,
    )];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![FactRole::DeviceBinding],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

pub fn enroll_continuity_slice_from_request(
    request: EnrollContinuityRequest,
    provider: &impl ContinuityVaultProvider,
    translator: &FenTranslator,
) -> Result<IdentityWorkflowSlice, VerticalSliceError> {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );
    let enrollment = provider.enroll(ContinuityEnrollmentRequest {
        subject_id: request.subject_id.clone(),
        modality: request.modality,
        requested_at: request.started_at.clone(),
    })?;
    let drafts =
        vec![translator.biometric_enrollment_added(enrollment, request.started_at.clone())];

    Ok(slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![FactRole::ContinuityWitness],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    ))
}

pub fn onboarding_identity_witnesses_slice_from_request(
    request: OnboardingIdentityWitnessesRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );

    let proofing_external_refs = request.identity_proofing.external_refs();
    let proofing_source_system = Some(request.identity_proofing.source_system());
    let mut drafts = Vec::new();
    let mut roles = Vec::new();

    let mut identity_proofing = translator.identity_witness_recorded(
        request.subject_id.clone(),
        request.identity_proofing.verified_at.clone(),
        request.identity_proofing.identity_witness_type(),
        request.subject_id.clone(),
        request.identity_proofing.assurance_level,
        request.identity_proofing.evidence_ref.clone(),
        request.identity_proofing.expires_at.clone(),
        proofing_source_system.clone(),
    );
    identity_proofing.external_refs = proofing_external_refs.clone();
    if let FactPayload::IdentityWitnessRecorded { context, .. } = &mut identity_proofing.payload {
        *context = request.identity_proofing.identity_witness_context();
    }
    drafts.push(identity_proofing);
    roles.push(FactRole::IdentityWitness);

    for asserted_attribute in &request.identity_proofing.asserted_attributes {
        let mut attribute = translator.identity_attribute_asserted(
            request.subject_id.clone(),
            request.identity_proofing.verified_at.clone(),
            asserted_attribute.attribute.clone(),
            asserted_attribute.value.clone(),
            asserted_attribute.confidence,
            proofing_source_system.clone(),
        );
        attribute.external_refs = proofing_external_refs.clone();
        drafts.push(attribute);
        roles.push(FactRole::IdentityWitness);
    }

    for risk_signal in request
        .identity_proofing
        .risk_signals
        .iter()
        .filter(|signal| signal.affects_policy)
    {
        let mut risk = translator.risk_evaluation(
            request.subject_id.clone(),
            request.identity_proofing.verified_at.clone(),
            risk_signal.action,
            risk_signal.result,
            risk_signal.required_assurance,
        );
        risk.provenance.source_system = proofing_source_system.clone();
        risk.external_refs = proofing_external_refs.clone();
        risk.external_refs.push(ExternalRef {
            system: ExternalSystem::Other(request.identity_proofing.provider_name.clone()),
            resource_type: Some("identity_proofing_risk_signal".to_string()),
            resource_id: risk_signal.signal_type.clone(),
            uri: None,
        });
        drafts.push(risk);
        roles.push(FactRole::RiskSignal);
    }

    let liveness =
        translator.selfie_liveness_witness_recorded(request.subject_id.clone(), request.liveness);
    drafts.push(liveness);
    roles.push(FactRole::IdentityWitness);

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        roles,
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

pub fn link_provider_identity_slice_from_request(
    request: LinkProviderIdentityRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );
    let drafts = vec![translator.clinical_identity_link_established(
        request.subject_id.clone(),
        request.started_at.clone(),
        request.provider_org,
        request.external_patient_ref,
        request.match_confidence,
        request.source_system,
    )];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![FactRole::InstitutionalLink],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

pub fn link_payer_identity_slice_from_request(
    request: LinkPayerIdentityRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );
    let drafts = vec![translator.payer_identity_link_established(
        request.subject_id.clone(),
        request.started_at.clone(),
        request.payer,
        request.member_ref,
        request.effective_period,
        request.source_system,
    )];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![FactRole::InstitutionalLink],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

pub fn onboarding_vertical_slice_from_request(
    request: OnboardingRequest,
    provider: &impl ContinuityVaultProvider,
    translator: &FenTranslator,
) -> Result<IdentityWorkflowSlice, VerticalSliceError> {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );

    let enrollment = provider.enroll(ContinuityEnrollmentRequest {
        subject_id: request.subject_id.clone(),
        modality: request.modality.clone(),
        requested_at: request.started_at.clone(),
    })?;

    let drafts = vec![
        translator.subject_created(
            request.subject_id.clone(),
            SubjectKind::HumanPerson,
            request.stable_profile,
            request.started_at.clone(),
        ),
        translator.device_binding_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.device_ref,
            AuthenticatorType::Passkey,
            AssuranceLevel::Medium,
            Some("AccountBootstrap".to_string()),
        ),
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::GovernmentIdVerification,
            request.subject_id.clone(),
            AssuranceLevel::High,
            Some("government-id-document".to_string()),
            None,
            Some("IdentityProofingVendor".to_string()),
        ),
        translator.biometric_enrollment_added(enrollment, request.started_at.clone()),
        translator.clinical_identity_link_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.provider_org,
            request.external_patient_ref,
            MatchConfidence::High,
            Some("FHIRLinker".to_string()),
        ),
        translator.payer_identity_link_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.payer,
            request.member_ref,
            None,
            Some("PayerLinker".to_string()),
        ),
    ];

    let fact_roles = vec![
        FactRole::IdentityAnchor,
        FactRole::DeviceBinding,
        FactRole::IdentityWitness,
        FactRole::ContinuityWitness,
        FactRole::InstitutionalLink,
        FactRole::InstitutionalLink,
    ];

    Ok(slice_from_drafts_with_id_plan(
        episode,
        drafts,
        fact_roles,
        request.authored_by,
        request.started_at,
        &request.id_plan,
    ))
}

pub fn onboarding_vertical_slice(
    subject_id: SubjectId,
    provider: &impl ContinuityVaultProvider,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> Result<IdentityWorkflowSlice, VerticalSliceError> {
    onboarding_vertical_slice_from_request(
        OnboardingRequest::fixture(subject_id, authored_by, started_at),
        provider,
        translator,
    )
}
