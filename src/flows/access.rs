use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRecordExportStepUpRequest {
    pub subject_id: SubjectId,
    pub enrollment_ref: String,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub challenge_expires_at: Timestamp,
    pub policy_ref: PolicyRef,
    pub device_ref: Option<DeviceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRecordExportStepUpOutcome {
    pub slice: IdentityWorkflowSlice,
    pub policy_evaluation: PolicyEvaluation,
    pub access_decision_fact_id: FactId,
}

impl CompleteRecordExportStepUpRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        enrollment_ref: String,
        authored_by: Author,
        started_at: Timestamp,
        challenge_expires_at: Timestamp,
        policy_ref: PolicyRef,
        device_ref: Option<DeviceRef>,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        let challenge_id = id_generator.next_challenge_id(&format!("challenge-{id_namespace}"));
        let nonce = id_generator
            .next_fact_id(&format!("nonce-{id_namespace}"))
            .0;
        let id_plan = WorkflowIdPlan::generated(id_generator, id_namespace, 4)
            .with_challenge(challenge_id, nonce);

        Self {
            subject_id,
            enrollment_ref,
            authored_by,
            started_at,
            id_plan,
            challenge_expires_at,
            policy_ref,
            device_ref,
        }
    }

    pub fn fixture(
        subject_id: SubjectId,
        enrollment_ref: String,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self {
            subject_id,
            enrollment_ref,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic_with_fact_overrides(
                "export",
                ProblemEpisodeId("episode-export-step-up".to_string()),
                4,
                vec![
                    (0, FactId("fact-export-credential".to_string())),
                    (1, FactId("fact-export-continuity".to_string())),
                    (2, FactId("fact-export-risk".to_string())),
                    (3, FactId("fact-export-access-decision".to_string())),
                ],
            )
            .with_challenge(
                ChallengeId("challenge-export-step-up".to_string()),
                "nonce-export-step-up".to_string(),
            ),
            challenge_expires_at: Timestamp("2026-05-29T00:10:00Z".to_string()),
            policy_ref: PolicyRef("complete-record-export-policy".to_string()),
            device_ref: Some("device-passkey-1".to_string()),
        }
    }
}

pub fn complete_record_export_step_up_slice_from_request(
    request: CompleteRecordExportStepUpRequest,
    provider: &impl ContinuityVaultProvider,
    nonce_lifecycle: &mut InMemoryNonceLifecycle,
    signature_verifier: &impl ContinuitySignatureVerifier,
    assurance_mapper: &impl ContinuityAssuranceMapper,
    translator: &FenTranslator,
) -> Result<IdentityWorkflowSlice, VerticalSliceError> {
    Ok(complete_record_export_step_up_outcome_from_request(
        request,
        provider,
        nonce_lifecycle,
        signature_verifier,
        assurance_mapper,
        translator,
    )?
    .slice)
}

pub fn complete_record_export_step_up_outcome_from_request(
    request: CompleteRecordExportStepUpRequest,
    provider: &impl ContinuityVaultProvider,
    nonce_lifecycle: &mut InMemoryNonceLifecycle,
    signature_verifier: &impl ContinuitySignatureVerifier,
    assurance_mapper: &impl ContinuityAssuranceMapper,
    translator: &FenTranslator,
) -> Result<CompleteRecordExportStepUpOutcome, VerticalSliceError> {
    let action = SensitiveAction::ExportCompleteRecord;
    let episode = access_authorization_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        action,
        request.authored_by.clone(),
        request.started_at.clone(),
    );

    let mut facts = Vec::new();
    let credential_fact = translator
        .credential_assertion(
            request.subject_id.clone(),
            request.started_at.clone(),
            AuthenticatorType::Passkey,
            request.device_ref,
            CredentialAssertionResult::Succeeded,
            AssuranceLevel::Medium,
            Some("AccountSession".to_string()),
        )
        .into_fact(request.id_plan.fact_id(0));
    facts.push(credential_fact.clone());

    let challenge = nonce_lifecycle
        .issue_challenge(ContinuityChallenge {
            challenge_id: request
                .id_plan
                .challenge_id_or(ChallengeId("challenge-export-step-up".to_string())),
            subject_id: request.subject_id.clone(),
            enrollment_ref: request.enrollment_ref,
            nonce: request.id_plan.nonce_or("nonce-export-step-up".to_string()),
            issued_at: request.started_at.clone(),
            expires_at: request.challenge_expires_at.clone(),
            intended_action: Some(action),
        })
        .map_err(VerticalSliceError::Verification)?;

    let signed_assertion = provider.signed_assertion(provider.prepare_challenge(challenge)?)?;
    let verification = verify_signed_continuity_assertion(
        signed_assertion.clone(),
        nonce_lifecycle,
        signature_verifier,
        assurance_mapper,
        request.started_at.clone(),
    );

    let (continuity_fact_id, continuity_assurance) = match verification {
        ContinuityAssertionVerificationResult::Verified {
            assertion,
            assurance_level,
        } => {
            let fact = translator
                .verified_continuity_assertion(
                    request.subject_id.clone(),
                    ContinuityAssertionVerificationResult::Verified {
                        assertion,
                        assurance_level,
                    },
                )
                .expect("verified continuity should translate")
                .into_fact(request.id_plan.fact_id(1));
            let continuity_fact_id = fact.id.clone();
            facts.push(fact);
            (Some(continuity_fact_id), Some(assurance_level))
        }
        ContinuityAssertionVerificationResult::Rejected { reason } => {
            let fact = translator
                .continuity_verification_rejected(
                    request.subject_id.clone(),
                    request.started_at.clone(),
                    &signed_assertion,
                    reason,
                )
                .into_fact(request.id_plan.fact_id(1));
            let rejection_fact_id = fact.id.clone();
            facts.push(fact);
            (Some(rejection_fact_id), None)
        }
    };

    let risk_fact = translator
        .risk_evaluation(
            request.subject_id.clone(),
            request.started_at.clone(),
            action,
            RiskEvaluationResult::Passed,
            AssuranceLevel::High,
        )
        .into_fact(request.id_plan.fact_id(2));
    facts.push(risk_fact.clone());

    let policy = default_policy_for_action(action, request.policy_ref);
    let policy_context = PolicyEvaluationContext::new(Some(request.started_at.clone()));
    let policy_evaluation = evaluate_action_policy_with_context(
        &policy,
        &EvidenceSummary {
            credential_fact_id: Some(credential_fact.id.clone()),
            credential_assurance: Some(AssuranceLevel::Medium),
            credential_observed_at: Some(request.started_at.clone()),
            continuity_fact_id,
            continuity_assurance,
            continuity_observed_at: Some(request.started_at.clone()),
            risk_fact_id: Some(risk_fact.id.clone()),
            risk_result: Some(RiskEvaluationResult::Passed),
            risk_observed_at: Some(request.started_at.clone()),
        },
        &policy_context,
    );

    let access_fact = translator
        .access_decision(
            request.subject_id,
            request.started_at.clone(),
            policy_evaluation.action,
            policy_evaluation.decision,
            policy_evaluation.relied_on_facts.clone(),
            policy_evaluation.policy_refs.clone(),
        )
        .into_fact(request.id_plan.fact_id(3));
    let access_decision_fact_id = access_fact.id.clone();
    facts.push(access_fact);

    let memberships = facts
        .iter()
        .zip([
            FactRole::IdentityWitness,
            FactRole::ContinuityWitness,
            FactRole::RiskSignal,
            FactRole::AccessDecisionEvidence,
        ])
        .enumerate()
        .map(|(index, (fact, role))| {
            episode_membership(
                request.id_plan.membership_id(index),
                fact.id.clone(),
                episode.id.clone(),
                role,
                request.authored_by.clone(),
                request.started_at.clone(),
            )
        })
        .collect();

    let slice = IdentityWorkflowSlice {
        episode,
        facts,
        memberships,
    };

    Ok(CompleteRecordExportStepUpOutcome {
        slice,
        policy_evaluation,
        access_decision_fact_id,
    })
}

pub fn complete_record_export_step_up_slice(
    subject_id: SubjectId,
    enrollment_ref: String,
    provider: &impl ContinuityVaultProvider,
    nonce_lifecycle: &mut InMemoryNonceLifecycle,
    signature_verifier: &impl ContinuitySignatureVerifier,
    assurance_mapper: &impl ContinuityAssuranceMapper,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> Result<IdentityWorkflowSlice, VerticalSliceError> {
    complete_record_export_step_up_slice_from_request(
        CompleteRecordExportStepUpRequest::fixture(
            subject_id,
            enrollment_ref,
            authored_by,
            started_at,
        ),
        provider,
        nonce_lifecycle,
        signature_verifier,
        assurance_mapper,
        translator,
    )
}
