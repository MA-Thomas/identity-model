use crate::continuity::*;
use crate::fen::*;
use crate::identity::*;
use crate::liveness::*;
use crate::provider::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactDraft {
    pub subject_id: SubjectId,
    pub occurred_at: TemporalAnchor,
    pub payload: FactPayload,
    pub provenance: Provenance,
    pub external_refs: Vec<ExternalRef>,
}

impl FactDraft {
    pub fn into_fact(self, id: FactId) -> Fact {
        Fact {
            id,
            subject_id: self.subject_id,
            occurred_at: self.occurred_at,
            code: None,
            payload: self.payload,
            status: FactStatus::Active,
            provenance: self.provenance,
            external_refs: self.external_refs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenTranslator {
    pub system_author: Author,
}

impl FenTranslator {
    pub fn subject_created(
        &self,
        subject_id: SubjectId,
        subject_kind: SubjectKind,
        stable_profile: StableIdentityProfile,
        occurred_at: Timestamp,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::SubjectCreated {
                subject_kind,
                stable_profile,
            },
            None,
            Vec::new(),
        )
    }

    pub fn biometric_enrollment_added(
        &self,
        enrollment: ContinuityEnrollment,
        occurred_at: Timestamp,
    ) -> FactDraft {
        let external_refs = provider_external_refs(&enrollment.provider_metadata);
        self.draft(
            enrollment.subject_id,
            occurred_at,
            FactPayload::BiometricEnrollmentReferenceAdded {
                biometric_system: enrollment.biometric_system,
                enrollment_ref: enrollment.enrollment_ref,
                modality: enrollment.modality,
            },
            Some(enrollment.provider_metadata.provider_name),
            external_refs,
        )
    }

    pub fn identity_witness_recorded(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        witness_type: IdentityWitnessType,
        target_subject_id: SubjectId,
        assurance_level: AssuranceLevel,
        evidence_ref: Option<DocumentRef>,
        expires_at: Option<Timestamp>,
        source_system: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::IdentityWitnessRecorded {
                witness_type,
                target_subject_id,
                assurance_level,
                evidence_ref,
                expires_at,
                context: IdentityWitnessContext::default(),
            },
            source_system,
            Vec::new(),
        )
    }

    pub fn selfie_liveness_witness_recorded(
        &self,
        subject_id: SubjectId,
        ceremony: VerifiedLivenessCeremony,
    ) -> FactDraft {
        self.draft(
            subject_id.clone(),
            ceremony.observed_at.clone(),
            FactPayload::IdentityWitnessRecorded {
                witness_type: IdentityWitnessType::SelfieLivenessCheck,
                target_subject_id: subject_id,
                assurance_level: ceremony.assurance_level,
                evidence_ref: None,
                expires_at: Some(ceremony.expires_at.clone()),
                context: ceremony.identity_witness_context(),
            },
            Some(ceremony.source_system()),
            ceremony.external_refs(),
        )
    }

    pub fn identity_attribute_asserted(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        attribute: IdentityAttribute,
        value: IdentityAttributeValue,
        confidence: MatchConfidence,
        source_system: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::IdentityAttributeAsserted {
                attribute,
                value,
                confidence,
            },
            source_system,
            Vec::new(),
        )
    }

    pub fn device_binding_established(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        device_ref: DeviceRef,
        authenticator_type: AuthenticatorType,
        assurance_level: AssuranceLevel,
        source_system: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::DeviceBindingEstablished {
                device_ref,
                authenticator_type,
                assurance_level,
            },
            source_system,
            Vec::new(),
        )
    }

    pub fn device_binding_revoked(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        device_ref: DeviceRef,
        reason: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::DeviceBindingRevoked { device_ref, reason },
            Some("FENIdentity".to_string()),
            Vec::new(),
        )
    }

    pub fn clinical_identity_link_established(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        provider_org: OrganizationRef,
        external_patient_ref: ExternalRef,
        match_confidence: MatchConfidence,
        source_system: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::ClinicalIdentityLinkEstablished {
                provider_org,
                external_patient_ref,
                match_confidence,
            },
            source_system,
            Vec::new(),
        )
    }

    pub fn clinical_identity_link_contested(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        link_fact_id: FactId,
        reason: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::ClinicalIdentityLinkContested {
                link_fact_id,
                reason,
            },
            Some("FENIdentityResolution".to_string()),
            Vec::new(),
        )
    }

    pub fn clinical_identity_link_dispute_resolved(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        link_fact_id: FactId,
        outcome: DisputeResolutionOutcome,
        rationale: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::ClinicalIdentityLinkDisputeResolved {
                link_fact_id,
                outcome,
                rationale,
            },
            Some("FENIdentityResolution".to_string()),
            Vec::new(),
        )
    }

    pub fn payer_identity_link_established(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        payer: String,
        member_ref: String,
        effective_period: Option<TimeInterval>,
        source_system: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::PayerIdentityLinkEstablished {
                payer,
                member_ref,
                effective_period,
            },
            source_system,
            Vec::new(),
        )
    }

    pub fn payer_identity_link_contested(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        link_fact_id: FactId,
        reason: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::PayerIdentityLinkContested {
                link_fact_id,
                reason,
            },
            Some("FENIdentityResolution".to_string()),
            Vec::new(),
        )
    }

    pub fn payer_identity_link_dispute_resolved(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        link_fact_id: FactId,
        outcome: DisputeResolutionOutcome,
        rationale: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::PayerIdentityLinkDisputeResolved {
                link_fact_id,
                outcome,
                rationale,
            },
            Some("FENIdentityResolution".to_string()),
            Vec::new(),
        )
    }

    pub fn duplicate_subject_merge_recorded(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        surviving_subject_id: SubjectId,
        merged_subject_ids: Vec<SubjectId>,
        reason: SubjectGraphCorrectionReason,
        evidence_refs: Vec<DocumentRef>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::DuplicateSubjectMergeRecorded {
                surviving_subject_id,
                merged_subject_ids,
                reason,
                evidence_refs,
            },
            Some("FENIdentityResolution".to_string()),
            Vec::new(),
        )
    }

    pub fn incorrect_merge_split_recorded(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        prior_subject_id: SubjectId,
        restored_subject_ids: Vec<SubjectId>,
        reason: SubjectGraphCorrectionReason,
        evidence_refs: Vec<DocumentRef>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::IncorrectMergeSplitRecorded {
                prior_subject_id,
                restored_subject_ids,
                reason,
                evidence_refs,
            },
            Some("FENIdentityResolution".to_string()),
            Vec::new(),
        )
    }

    pub fn identity_witness_superseded(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        superseded_witness_fact_id: FactId,
        replacement_witness_fact_id: FactId,
        reason: SupersessionReason,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::IdentityWitnessSuperseded {
                superseded_witness_fact_id,
                replacement_witness_fact_id,
                reason,
            },
            Some("FENIdentityResolution".to_string()),
            Vec::new(),
        )
    }

    pub fn verified_continuity_assertion(
        &self,
        subject_id: SubjectId,
        verification: ContinuityAssertionVerificationResult,
    ) -> Option<FactDraft> {
        match verification {
            ContinuityAssertionVerificationResult::Verified {
                assertion,
                assurance_level,
            } => {
                let occurred_at = assertion.timestamp.clone();
                let source_system = Some(assertion.provider_metadata.provider_name.clone());
                let external_refs = provider_external_refs(&assertion.provider_metadata);
                Some(self.draft(
                    subject_id,
                    occurred_at,
                    assertion.to_biometric_continuity_fact_payload(assurance_level),
                    source_system,
                    external_refs,
                ))
            }
            ContinuityAssertionVerificationResult::Rejected { .. } => None,
        }
    }

    pub fn continuity_verification_rejected(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        signed_assertion: &SignedContinuityAssertion,
        reason: ContinuityAssertionRejectionReason,
    ) -> FactDraft {
        let provider_metadata = &signed_assertion.assertion.provider_metadata;
        let external_refs = provider_external_refs(provider_metadata);

        self.draft(
            subject_id,
            occurred_at,
            FactPayload::ContinuityVerificationRejected {
                biometric_system: Some(provider_metadata.provider_name.clone()),
                enrollment_ref: signed_assertion.assertion.enrollment_ref.clone(),
                challenge_nonce: signed_assertion.assertion.challenge_nonce.clone(),
                reason: reason.into(),
            },
            Some(provider_metadata.provider_name.clone()),
            external_refs,
        )
    }

    pub fn credential_assertion(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        authenticator_type: AuthenticatorType,
        device_ref: Option<DeviceRef>,
        result: CredentialAssertionResult,
        assurance_level: AssuranceLevel,
        source_system: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::CredentialAssertion {
                authenticator_type,
                device_ref,
                result,
                assurance_level,
            },
            source_system,
            Vec::new(),
        )
    }

    pub fn risk_evaluation(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        action: SensitiveAction,
        result: RiskEvaluationResult,
        required_assurance: AssuranceLevel,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::RiskEvaluationEvent {
                action,
                result,
                required_assurance,
            },
            Some("FENRiskEngine".to_string()),
            Vec::new(),
        )
    }

    pub fn access_decision(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        action: SensitiveAction,
        decision: AccessDecisionResult,
        relied_on_facts: Vec<FactId>,
        policy_refs: Vec<PolicyRef>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::AccessDecision {
                action,
                decision,
                relied_on_facts,
                policy_refs,
            },
            Some("FENPolicyEngine".to_string()),
            Vec::new(),
        )
    }

    pub fn authority_relationship_established(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        actor_subject_id: SubjectId,
        target_subject_id: SubjectId,
        authority_type: AuthorityType,
        scope: AuthorityScope,
        valid_period: Option<TimeInterval>,
        evidence_ref: Option<DocumentRef>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::AuthorityRelationshipEstablished {
                actor_subject_id,
                target_subject_id,
                authority_type,
                scope,
                valid_period,
                evidence_ref,
            },
            Some("FENAuthority".to_string()),
            Vec::new(),
        )
    }

    pub fn authority_relationship_revoked(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        relationship_fact_id: FactId,
        reason: Option<String>,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::AuthorityRelationshipRevoked {
                relationship_fact_id,
                reason,
            },
            Some("FENAuthority".to_string()),
            Vec::new(),
        )
    }

    pub fn account_recovery_event(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        method: RecoveryMethod,
        result: RecoveryResult,
        assurance_level: AssuranceLevel,
    ) -> FactDraft {
        self.draft(
            subject_id,
            occurred_at,
            FactPayload::AccountRecoveryEvent {
                method,
                result,
                assurance_level,
            },
            Some("FENRecovery".to_string()),
            Vec::new(),
        )
    }

    fn draft(
        &self,
        subject_id: SubjectId,
        occurred_at: Timestamp,
        payload: FactPayload,
        source_system: Option<String>,
        external_refs: Vec<ExternalRef>,
    ) -> FactDraft {
        FactDraft {
            subject_id,
            occurred_at: TemporalAnchor::Point(occurred_at.clone()),
            payload,
            provenance: Provenance {
                source_system,
                source_document: None,
                imported_at: occurred_at,
                author: self.system_author.clone(),
                // Provider adapters translate evidence delivered over the
                // provider's API on the subject's behalf.
                tier: ProvenanceTier::ApiSourced,
                content_hash: None,
                authorization_basis: None,
            },
            external_refs,
        }
    }
}

fn provider_external_refs(metadata: &ContinuityProviderMetadata) -> Vec<ExternalRef> {
    let mut refs = Vec::new();

    if let Some(provider_event_id) = &metadata.provider_event_id {
        refs.push(ExternalRef {
            system: ExternalSystem::ContinuityProvider,
            resource_type: Some("provider_event".to_string()),
            resource_id: provider_event_id.clone(),
            uri: None,
        });
    }

    if let Some(provider_subject_ref) = &metadata.provider_subject_ref {
        refs.push(ExternalRef {
            system: ExternalSystem::ContinuityProvider,
            resource_type: Some("provider_subject".to_string()),
            resource_id: provider_subject_ref.clone(),
            uri: None,
        });
    }

    refs
}
