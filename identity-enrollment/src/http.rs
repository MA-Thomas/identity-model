use identity_application::enrollment::{ports::EnrollmentStore, Clock, EnrollmentService};
use identity_contract::{Error, Response, SignedRequest};
use identity_model::OidcSessionVerifier;
use std::sync::Arc;
/// Bounded transport; hosts terminate TLS before the loopback listener.
pub fn router<R, V, C>(service: Arc<EnrollmentService<R, V, C>>) -> axum::Router
where
    R: EnrollmentStore + 'static,
    V: OidcSessionVerifier + Send + Sync + 'static,
    C: Clock + 'static,
{
    use axum::{extract::DefaultBodyLimit, routing::post, Json, Router};
    let capacity = Arc::new(tokio::sync::Semaphore::new(32));
    Router::new()
        .route(
            "/v1/enrollment",
            post(move |Json(request): Json<SignedRequest>| {
                let service = service.clone();
                let capacity = capacity.clone();
                async move {
                    let Ok(permit) = capacity.try_acquire_owned() else {
                        return Json(Response::Rejected(Error::Unavailable));
                    };
                    // A disconnected HTTP caller must not release capacity while verification continues.
                    let task = tokio::spawn(async move {
                        let _permit = permit;
                        service.handle(&request).await
                    });
                    Json(match task.await {
                        Ok(Ok(response)) => response,
                        Ok(Err(error)) => {
                            eprintln!("identity request failed: {error}");
                            Response::Rejected(error.code())
                        }
                        Err(error) => {
                            eprintln!("identity request task failed (panic: {})", error.is_panic());
                            Response::Rejected(Error::Unavailable)
                        }
                    })
                }
            }),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
}
