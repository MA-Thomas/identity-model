//! Pure enrollment policy over verified evidence. Constructors stay within the service.
use identity_contract::*;
use identity_model::{
    time, validate_oidc_session_context, OidcSessionVerifier, VerifiedOidcSession,
};
pub(crate) struct Evidence {
    pub session: VerifiedOidcSession,
    pub ownership: Ownership,
    pub expires_at: i64,
}
pub(crate) fn verify(
    verifier: &impl OidcSessionVerifier,
    config: &super::Config,
    intent: &EnrollmentIntent,
    token: &str,
    bank: &SignedBankOwnership,
    device: &[u8],
    now: i64,
) -> Result<Evidence, Error> {
    intent.validate(now)?;
    intent.verify_possession(device)?;
    let timestamp = time::unix_seconds_to_timestamp(now);
    let session = verifier
        .verify_session(token, &config.oidc, &timestamp)
        .map_err(|_| Error::Unauthorized)?;
    validate_oidc_session_context(&session, &config.oidc, &timestamp)
        .map_err(|_| Error::Unauthorized)?;
    if session.nonce.as_deref() != Some(&intent.challenge) {
        return Err(Error::Context);
    }
    let authenticated = session
        .auth_time
        .as_ref()
        .ok_or(Error::Unauthorized)
        .and_then(|t| time::timestamp_to_unix_seconds(t).map_err(|_| Error::Unauthorized))?;
    if authenticated > now || now - authenticated > MAX_LIFETIME {
        return Err(Error::Expired);
    }
    let ownership = bank.verify(
        &config.bank_key,
        intent,
        &session.issuer,
        &session.subject,
        now,
    )?;
    let expires_at = intent
        .expires_at
        .min(
            authenticated
                .checked_add(MAX_LIFETIME)
                .ok_or(Error::Invalid)?,
        )
        .min(bank.claims.expires_at)
        .min(time::timestamp_to_unix_seconds(&session.expires_at).map_err(|_| Error::Invalid)?);
    Ok(Evidence {
        session,
        ownership,
        expires_at,
    })
}
