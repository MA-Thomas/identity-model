use identity_contract::Error;
/// Driver failures retain their cause without making a driver part of the application API.
#[derive(Debug)]
pub enum ServiceError {
    Contract(Error),
    Storage {
        code: Error,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    VerificationTask(tokio::task::JoinError),
}
impl ServiceError {
    pub fn code(&self) -> Error {
        match self {
            Self::Contract(code) | Self::Storage { code, .. } => *code,
            Self::VerificationTask(_) => Error::Unavailable,
        }
    }
}
impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contract(e) => e.fmt(f),
            Self::Storage { .. } => f.write_str("identity storage failed"),
            Self::VerificationTask(_) => f.write_str("identity verification task failed"),
        }
    }
}
impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Contract(e) => e,
            Self::Storage { source, .. } => source.as_ref(),
            Self::VerificationTask(e) => e,
        })
    }
}
impl From<Error> for ServiceError {
    fn from(e: Error) -> Self {
        Self::Contract(e)
    }
}
impl From<tokio::task::JoinError> for ServiceError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::VerificationTask(e)
    }
}
