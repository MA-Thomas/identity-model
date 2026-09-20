#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};
use std::future::Future;

pub(super) fn sqlx_error(error: sqlx::Error) -> PostgresAdapterError {
    PostgresAdapterError::Sqlx(error.to_string())
}

pub(super) fn fen_store_postgres_error(
    error: fen_store_postgres::FenStorePostgresError,
) -> PostgresAdapterError {
    use fen_store_postgres::FenStorePostgresError as SharedError;

    match error {
        SharedError::AppendSequenceOutOfRange => PostgresAdapterError::AppendSequenceOutOfRange,
        SharedError::NegativeAppendSequence => PostgresAdapterError::NegativeAppendSequence,
        SharedError::InvalidTemporalAnchor => PostgresAdapterError::InvalidTemporalAnchor,
        SharedError::UnknownTemporalKind(value) => PostgresAdapterError::UnknownTemporalKind(value),
        SharedError::UnknownFactStatusKind(value) => {
            PostgresAdapterError::UnknownFactStatusKind(value)
        }
        SharedError::InvalidFactStatusPayload => PostgresAdapterError::InvalidFactStatusPayload,
        SharedError::UnknownAuthorType(value) => PostgresAdapterError::UnknownAuthorType(value),
        SharedError::UnknownSupersessionReason(value) => {
            PostgresAdapterError::UnknownSupersessionReason(value)
        }
        SharedError::UnknownPayloadType(value) => PostgresAdapterError::UnknownPayloadType(value),
        SharedError::UnknownEncryptionAlgorithm(value) => {
            PostgresAdapterError::UnknownEncryptionAlgorithm(value)
        }
        SharedError::UnknownAssociatedDataVersion(value) => {
            PostgresAdapterError::UnknownAssociatedDataVersion(value)
        }
        SharedError::UnknownMaterializationAuditOutcome(value) => {
            PostgresAdapterError::UnknownMaterializationAuditOutcome(value)
        }
        SharedError::UnknownMaterializationError(value) => {
            PostgresAdapterError::UnknownMaterializationError(value)
        }
        SharedError::StatusPayloadJson(value) => PostgresAdapterError::StatusPayloadJson(value),
        SharedError::Store(EncryptedFactStoreError::DuplicateFactId) => {
            PostgresAdapterError::Repository(RepositoryError::DuplicateFactId)
        }
        SharedError::Store(EncryptedFactStoreError::DuplicateAppendSequence) => {
            PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence)
        }
        SharedError::Sqlx(value) => PostgresAdapterError::Sqlx(value),
    }
}

pub(super) fn repository_sqlx_error(error: sqlx::Error) -> PostgresAdapterError {
    if let sqlx::Error::Database(database_error) = &error {
        match database_error.constraint() {
            Some("identity_facts_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateFactId)
            }
            Some("identity_facts_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            Some("identity_episodes_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateEpisodeId)
            }
            Some("identity_episodes_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            Some("identity_episode_memberships_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateMembershipId)
            }
            Some("identity_episode_memberships_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            Some("identity_episode_relations_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateRelationId)
            }
            Some("identity_episode_relations_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            _ => {}
        }
    }
    sqlx_error(error)
}

pub(super) fn app_attest_sqlx_error(error: sqlx::Error) -> AppAttestAssertionVerificationError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.constraint() == Some("identity_app_attest_challenge_nonces_pkey") {
            return AppAttestAssertionVerificationError::ChallengeReplay;
        }
        if database_error.constraint() == Some("identity_app_attest_key_registrations_pkey") {
            return AppAttestAssertionVerificationError::KeyContextMismatch;
        }
    }
    AppAttestAssertionVerificationError::KeyStateUnavailable
}

pub(super) fn live_presence_challenge_sqlx_error(error: sqlx::Error) -> LivePresenceChallengeError {
    if let sqlx::Error::Database(database_error) = &error {
        match database_error.constraint() {
            Some("identity_live_presence_challenges_pkey") => {
                return LivePresenceChallengeError::DuplicateChallengeId
            }
            Some("identity_live_presence_challenges_challenge_nonce_key") => {
                return LivePresenceChallengeError::DuplicateChallengeNonce
            }
            _ => {}
        }
    }
    LivePresenceChallengeError::StorageUnavailable
}

pub(super) fn run_app_attest_store_blocking<T, F, Fut>(
    operation: F,
) -> Result<T, AppAttestAssertionVerificationError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, AppAttestAssertionVerificationError>> + Send + 'static,
{
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        runtime.block_on(operation())
    });
    handle.join().unwrap_or(Err(
        AppAttestAssertionVerificationError::KeyStateUnavailable,
    ))
}

pub(super) fn run_live_presence_challenge_store_blocking<T, F, Fut>(
    operation: F,
) -> Result<T, LivePresenceChallengeError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, LivePresenceChallengeError>> + Send + 'static,
{
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        runtime.block_on(operation())
    });
    handle
        .join()
        .unwrap_or(Err(LivePresenceChallengeError::StorageUnavailable))
}

pub(super) fn postgres_terminal_live_presence_challenge_status_for_error(
    error: LivePresenceChallengeError,
    observed_at: Timestamp,
) -> Option<LivePresenceChallengeStatus> {
    match error {
        LivePresenceChallengeError::ChallengeExpired => {
            Some(LivePresenceChallengeStatus::Expired {
                expired_at: observed_at,
            })
        }
        LivePresenceChallengeError::ChallengeNonceMismatch => {
            Some(LivePresenceChallengeStatus::Failed {
                failed_at: observed_at,
                reason: LivePresenceChallengeFailureReason::ChallengeMismatch,
                provider_event_id: None,
            })
        }
        LivePresenceChallengeError::SubjectMismatch => Some(LivePresenceChallengeStatus::Failed {
            failed_at: observed_at,
            reason: LivePresenceChallengeFailureReason::SubjectMismatch,
            provider_event_id: None,
        }),
        LivePresenceChallengeError::DeviceMismatch => Some(LivePresenceChallengeStatus::Failed {
            failed_at: observed_at,
            reason: LivePresenceChallengeFailureReason::DeviceMismatch,
            provider_event_id: None,
        }),
        LivePresenceChallengeError::AppContextMismatch => {
            Some(LivePresenceChallengeStatus::Failed {
                failed_at: observed_at,
                reason: LivePresenceChallengeFailureReason::AppContextMismatch,
                provider_event_id: None,
            })
        }
        _ => None,
    }
}
