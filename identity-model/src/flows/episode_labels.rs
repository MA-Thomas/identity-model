//! Human-facing episode labels for generated demo/workflow slices.
//!
//! Labels are presentation metadata on `ProblemEpisode`; they are not inputs to
//! policy, projection, or identity decisions.

use super::*;

pub(super) fn access_authorization_label(action: SensitiveAction) -> String {
    match action {
        SensitiveAction::ViewRecord => "View record authorization",
        SensitiveAction::ShareRecord => "Share record authorization",
        SensitiveAction::ExportCompleteRecord => "Complete record export authorization",
        SensitiveAction::LinkProvider => "Provider link authorization",
        SensitiveAction::LinkPayer => "Payer link authorization",
        SensitiveAction::ChangeRecoveryMethod => "Recovery method change authorization",
        SensitiveAction::DelegateAuthority => "Authority delegation authorization",
        SensitiveAction::RevokeAuthority => "Authority revocation authorization",
        SensitiveAction::AuthorizeDataTransaction => "Data transaction authorization",
        SensitiveAction::EmergencyAccess => "Emergency access authorization",
    }
    .to_string()
}
