//! PostgreSQL implementation of the identity application's atomic ownership contracts.
use identity_application::enrollment::{evidence::EvidenceFingerprints, ports::*, ServiceError};
use identity_model::{fen::SubjectId, login::ProductLoginIdentity};

use identity_contract::{changes::*, evidence::*, *};

use tokio::sync::Mutex;

use tokio_postgres::{types::Json, Client, Transaction};

#[derive(Debug)]
enum StoreError {
    Database(tokio_postgres::Error),
    Application(ServiceError),
}
impl From<tokio_postgres::Error> for StoreError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Database(e)
    }
}
impl From<Error> for StoreError {
    fn from(e: Error) -> Self {
        Self::Application(e.into())
    }
}
impl From<ServiceError> for StoreError {
    fn from(e: ServiceError) -> Self {
        Self::Application(e)
    }
}
impl From<StoreError> for ServiceError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Application(e) => e,
            StoreError::Database(e) => Self::Storage {
                code: if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                    Error::Conflict
                } else {
                    Error::Unavailable
                },
                source: Box::new(e),
            },
        }
    }
}
async fn finish<T>(
    future: impl std::future::Future<Output = Result<T, StoreError>>,
) -> Result<T, ServiceError> {
    future.await.map_err(Into::into)
}
pub struct PostgresEnrollmentStore {
    db: Mutex<Client>,
}
impl PostgresEnrollmentStore {
    /// The host owns the connection task. Schema initialization is adapter-owned.
    pub async fn new(mut db: Client) -> Result<Self, ServiceError> {
        migrate(&mut db).await?;

        Ok(Self { db: Mutex::new(db) })
    }
}
async fn login_lock(
    tx: &Transaction<'_>,
    product: &str,
    login: (&str, &str),
) -> Result<(), StoreError> {
    let key = serde_json::to_string(&(product, login)).map_err(|_| Error::Invalid)?;

    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext($1))",
        &[&format!("identity-login:{key}")],
    )
    .await?;

    Ok(())
}
async fn operation_lock(
    tx: &Transaction<'_>,
    product: &str,
    operation: &str,
) -> Result<(), StoreError> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext($1))",
        &[&format!("identity-enrollment:{product}:{operation}")],
    )
    .await?;

    Ok(())
}
/// Serializes screening of one product's enrollments, so two overlapping applicants
/// cannot both miss each other.
async fn evidence_lock(tx: &Transaction<'_>, product: &str) -> Result<(), StoreError> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext($1))",
        &[&format!("identity-evidence:{product}")],
    )
    .await?;
    Ok(())
}
fn fingerprints(
    rows: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> Result<EvidenceFingerprints, StoreError> {
    let mut parsed = Vec::new();
    for (field, value) in rows {
        parsed.push((
            EvidenceField::parse(&field)?,
            value.try_into().map_err(|_| Error::Invalid)?,
        ));
    }
    Ok(EvidenceFingerprints::from_recorded(parsed)?)
}
async fn recorded_evidence(
    tx: &Transaction<'_>,
    product: &str,
    operation: &str,
) -> Result<Option<EvidenceFingerprints>, StoreError> {
    let rows = tx
        .query(
            "SELECT field,fingerprint FROM shared_identity_evidence WHERE product=$1 AND operation=$2",
            &[&product, &operation],
        )
        .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    Ok(Some(fingerprints(
        rows.into_iter().map(|row| (row.get(0), row.get(1))),
    )?))
}
/// The product's other enrollments sharing any fingerprint with `evidence`. The query
/// over-selects; the policy decides which overlaps matter.
async fn candidates(
    tx: &Transaction<'_>,
    product: &str,
    operation: &str,
    evidence: &EvidenceFingerprints,
) -> Result<Vec<EvidenceCandidate>, StoreError> {
    let fields: Vec<&str> = evidence.iter().map(|(field, _)| field.as_str()).collect();
    let values: Vec<&[u8]> = evidence.iter().map(|(_, value)| value.as_slice()).collect();
    let rows = tx
        .query(
            "SELECT operation,account,field,fingerprint FROM shared_identity_evidence WHERE product=$1 AND operation<>$2 AND operation IN (SELECT operation FROM shared_identity_evidence WHERE product=$1 AND field=ANY($3) AND fingerprint=ANY($4)) ORDER BY operation,field",
            &[&product, &operation, &fields, &values],
        )
        .await?;
    // Operation -> (account, recorded field fingerprints).
    type Recorded = (String, Vec<(String, Vec<u8>)>);
    let mut grouped = std::collections::BTreeMap::<String, Recorded>::new();
    for row in rows {
        grouped
            .entry(row.get(0))
            .or_insert_with(|| (row.get(1), Vec::new()))
            .1
            .push((row.get(2), row.get(3)));
    }
    grouped
        .into_values()
        .map(|(account, rows)| {
            Ok(EvidenceCandidate {
                account,
                fingerprints: fingerprints(rows)?,
            })
        })
        .collect()
}
/// A case as opened, with its decision when one is recorded.
fn review_case(
    opened: ReviewCase,
    decision: Option<ReviewDecision>,
) -> Result<ReviewCase, StoreError> {
    if opened.decision.is_some() {
        return Err(Error::Invalid.into());
    }
    Ok(ReviewCase { decision, ..opened })
}
const CASE_SELECT: &str = "SELECT r.opened,d.decision FROM shared_identity_reviews r LEFT JOIN shared_identity_review_decisions d USING(product,id)";
fn case_from(row: &tokio_postgres::Row) -> Result<ReviewCase, StoreError> {
    review_case(
        row.get::<_, Json<ReviewCase>>(0).0,
        row.get::<_, Option<Json<ReviewDecision>>>(1).map(|d| d.0),
    )
}
async fn operation_case(
    db: &impl tokio_postgres::GenericClient,
    product: &str,
    operation: &str,
) -> Result<Option<ReviewCase>, StoreError> {
    db.query_opt(
        &format!("{CASE_SELECT} WHERE r.product=$1 AND r.operation=$2"),
        &[&product, &operation],
    )
    .await?
    .map(|row| case_from(&row))
    .transpose()
}
/// The product-enrollment schema, applied in order.
const MIGRATIONS: [(i32, &str); 2] = [
    (
        2,
        include_str!("../migrations/0002_product_login_enrollment.sql"),
    ),
    (
        6,
        include_str!("../migrations/0006_product_enrollment_review.sql"),
    ),
];
async fn migrate(db: &mut Client) -> Result<(), StoreError> {
    let tx = db.transaction().await?;

    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext('shared-identity-migration'))",
        &[],
    )
    .await?;

    tx.batch_execute(
        "CREATE TABLE IF NOT EXISTS shared_identity_schema_migrations(version INTEGER PRIMARY KEY)",
    )
    .await?;

    let applied: Vec<i32> = tx
        .query(
            "SELECT version FROM shared_identity_schema_migrations ORDER BY version",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    let known: Vec<i32> = MIGRATIONS.iter().map(|(version, _)| *version).collect();
    if !known.starts_with(&applied) {
        return Err(ServiceError::Storage {
            code: Error::Unavailable,
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the shared-identity schema has versions this build does not know; use a fresh database",
            )),
        }
        .into());
    }
    for (version, sql) in &MIGRATIONS[applied.len()..] {
        tx.batch_execute(sql).await?;
        tx.execute(
            "INSERT INTO shared_identity_schema_migrations(version) VALUES($1)",
            &[version],
        )
        .await?;
    }
    tx.commit().await?;

    Ok(())
}

impl EnrollmentStore for PostgresEnrollmentStore {
    async fn existing(
        &self,
        intent: &EnrollmentIntent,
        hash: &[u8; 32],
    ) -> Result<Option<Response>, ServiceError> {
        finish(async {
    let db = self.db.lock().await;

    match db.query_opt("SELECT request_digest,response FROM shared_identity_attempts WHERE product=$1 AND operation=$2 AND challenge=$3", &[&intent.product,&intent.operation,&intent.challenge]).await? {
        None => Ok(None),
        Some(row) => {
            if row.get::<_,Vec<u8>>(0) != hash { return Err(Error::Conflict.into());
 }
            Ok(Some(row.get::<_,Json<Response>>(1).0))
        }
    }
    }).await
    }
    async fn lookup(&self, product: &str, operation: &str) -> Result<LookupRecord, ServiceError> {
        finish(async {
            let db = self.db.lock().await;
            let response = db.query_opt("SELECT response FROM shared_identity_attempts WHERE product=$1 AND operation=$2 ORDER BY created_at DESC LIMIT 1", &[&product,&operation]).await?.map(|r| r.get::<_,Json<Response>>(0).0);
            let case = operation_case(&*db, product, operation).await?;
            Ok(LookupRecord { response, case })
        })
        .await
    }
    async fn reviews(&self, product: &str) -> Result<Vec<ReviewCase>, ServiceError> {
        finish(async {
            let db = self.db.lock().await;
            db.query(
                &format!("{CASE_SELECT} WHERE r.product=$1 AND d.id IS NULL ORDER BY r.opened_at, r.id LIMIT 100"),
                &[&product],
            )
            .await?
            .iter()
            .map(case_from)
            .collect()
        })
        .await
    }
    async fn resolve(
        &self,
        product: &str,
        case: &ReviewCaseId,
        decide: impl FnOnce(ReviewCase) -> Result<ResolutionDecision, ServiceError> + Send,
    ) -> Result<ReviewCase, ServiceError> {
        finish(async {
            let mut db = self.db.lock().await;
            let tx = db.transaction().await?;
            // A case's operation never changes; take the operation's lock before its rows
            // so the decision serializes with the applicant's attempts.
            let operation: String = tx
                .query_opt(
                    "SELECT operation FROM shared_identity_reviews WHERE product=$1 AND id=$2",
                    &[&product, &case.as_str()],
                )
                .await?
                .ok_or(Error::Invalid)?
                .get(0);
            operation_lock(&tx, product, &operation).await?;
            let current = operation_case(&tx, product, &operation).await?.ok_or(Error::Invalid)?;
            let (resolved, decision) = decide(current)?.into_parts();
            if let Some(decision) = decision {
                tx.execute(
                    "INSERT INTO shared_identity_review_decisions(product,id,decision) VALUES($1,$2,$3)",
                    &[&product, &case.as_str(), &Json(&decision)],
                )
                .await?;
            }
            tx.commit().await?;
            Ok(resolved)
        })
        .await
    }
    async fn confirm(
        &self,
        product: &str,
        decision: &SignedDecision,
    ) -> Result<Response, ServiceError> {
        finish(async {
    let mut db = self.db.lock().await;

    let tx = db.transaction().await?;

    let intent = &decision.claims.intent;

    operation_lock(&tx, product, &intent.operation).await?;

    let response = Response::Eligible(Box::new(decision.clone()));

    if tx.query_opt("SELECT 1 FROM shared_identity_attempts WHERE product=$1 AND operation=$2 AND challenge=$3 AND response=$4", &[&product,&intent.operation,&intent.challenge,&Json(response)]).await?.is_none() { return Err(Error::Conflict.into());
 }
    let count = tx.execute("UPDATE shared_identity_enrollments SET confirmed=TRUE WHERE product=$1 AND operation=$2 AND account=$3 AND subject_ref=$4", &[&product,&intent.operation,&intent.account,&decision.claims.subject_ref.as_str()]).await?;

    if count != 1 {
        return Err(Error::Conflict.into());

    }
    tx.commit().await?;

    Ok(Response::Confirmed)
    }).await
    }
    async fn security_events(
        &self,
        product: &str,
        subject: &ProductSubjectRef,
        after: u64,
    ) -> Result<Response, ServiceError> {
        finish(async {
    let after = i64::try_from(after).map_err(|_| Error::Invalid)?;

    let db = self.db.lock().await;

    let events = db.query("SELECT event FROM shared_identity_security_events WHERE product=$1 AND subject_ref=$2 AND security_version>$3 ORDER BY security_version LIMIT 100", &[&product,&subject.as_str(),&after]).await?.into_iter().map(|row|row.get::<_,Json<changes::SignedSecurityEvent>>(0).0).collect();

    Ok(Response::SecurityEvents(events))
    }).await
    }
    async fn existing_change(
        &self,
        product: &str,
        operation: &str,
        hash: &[u8; 32],
    ) -> Result<Option<Response>, ServiceError> {
        finish(async {
    let db = self.db.lock().await;

    if let Some(row) = db.query_opt("SELECT event,request_digest FROM shared_identity_security_events WHERE product=$1 AND operation=$2", &[&product,&operation]).await? {
        if row.get::<_,Vec<u8>>(1) != hash { return Err(Error::Conflict.into());
 }
        return Ok(Some(Response::IdentityChanged(Box::new(row.get::<_,Json<changes::SignedSecurityEvent>>(0).0))));

    }
    Ok(None)
    }).await
    }

    async fn record(
        &self,
        scope: EnrollmentScope<'_>,
        decide: impl FnOnce(EnrollmentContext) -> Result<EnrollmentDecision, ServiceError> + Send,
    ) -> Result<Response, ServiceError> {
        finish(async {
        let mut db=self.db.lock().await;
 let tx=db.transaction().await?;

        login_lock(&tx,scope.product,scope.login).await?;

        operation_lock(&tx,scope.product,&scope.intent.operation).await?;

        let prior=tx.query_opt("SELECT intent,request_digest,response FROM shared_identity_attempts WHERE product=$1 AND operation=$2 ORDER BY created_at DESC LIMIT 1", &[&scope.product,&scope.intent.operation]).await?.map(|r|PriorAttempt {intent:r.get::<_,Json<EnrollmentIntent>>(0).0,digest:r.get(1),response:r.get::<_,Json<Response>>(2).0});

        // The product scopes both the protected lookup and external-login ownership.
        let login=if let Some(row)=tx.query_opt(
            "SELECT s.subject_id,s.status,r.subject_ref,l.issuer,l.login_subject FROM shared_identity_product_logins l JOIN shared_identity_subjects s USING(subject_id) JOIN shared_identity_product_refs r ON r.product=l.product AND r.subject_id=l.subject_id WHERE l.product=$1 AND l.issuer=$2 AND l.login_subject=$3 FOR UPDATE OF s,l",
            &[&scope.product,&scope.login.0,&scope.login.1],
        ).await? {
            let identity = ProductLoginIdentity::new(scope.product.into(), SubjectId(row.get(0)), row.get(3), row.get(4)).map_err(|_| Error::Invalid)?;
            Some(LoginOwner {identity,status:row.get(1),product_ref:row.get::<_,String>(2).try_into()?})
        }else{None};

        let enrollment=tx.query_opt("SELECT account,subject_ref,confirmed FROM shared_identity_enrollments WHERE product=$1 AND operation=$2 FOR UPDATE", &[&scope.product,&scope.intent.operation]).await?.map(|r|EnrollmentOwner {account:r.get(0),subject_ref:r.get(1),confirmed:r.get(2)});

        let recorded=recorded_evidence(&tx,scope.product,&scope.intent.operation).await?;
        let case=operation_case(&tx,scope.product,&scope.intent.operation).await?;
        let candidates=if let Some(evidence)=scope.evidence {
            evidence_lock(&tx,scope.product).await?;
            candidates(&tx,scope.product,&scope.intent.operation,evidence).await?
        } else { Vec::new() };

        let (response,writes)=decide(EnrollmentContext {prior,enrollment,login,screening:ScreeningContext{recorded,case,candidates}})?.into_parts();

        if let Some(writes)=writes {
            if let Some((subject,status))=writes.subject {tx.execute("INSERT INTO shared_identity_subjects(subject_id,status) VALUES($1,$2)", &[&subject.as_str(),&status]).await?;
}
            if let Some((subject,reference))=writes.product_ref {
                tx.execute("INSERT INTO shared_identity_product_refs(product,subject_id,subject_ref) VALUES($1,$2,$3)", &[&scope.product,&subject.as_str(),&reference.as_str()]).await?;
            }
            if let Some(login)=writes.login {
                tx.execute("INSERT INTO shared_identity_product_logins(product,subject_id,issuer,login_subject) VALUES($1,$2,$3,$4)", &[&login.product(),&login.subject().as_str(),&login.issuer(),&login.external_subject()]).await?;
            }
            if let Some(binding)=writes.enrollment {
                tx.execute("INSERT INTO shared_identity_enrollments(product,operation,account,subject_id,subject_ref) VALUES($1,$2,$3,$4,$5)", &[&scope.product,&scope.intent.operation,&binding.account,&binding.subject.as_str(),&binding.subject_ref.as_str()]).await?;
            }
            if let Some((account,evidence))=writes.evidence {
                for (field,value) in evidence.iter() {
                    tx.execute("INSERT INTO shared_identity_evidence(product,operation,account,field,fingerprint) VALUES($1,$2,$3,$4,$5)", &[&scope.product,&scope.intent.operation,&account,&field.as_str(),&value.as_slice()]).await?;
                }
            }
            if let Some(case)=writes.review {
                tx.execute("INSERT INTO shared_identity_reviews(product,id,operation,opened_at,opened) VALUES($1,$2,$3,$4,$5)", &[&scope.product,&case.id.as_str(),&case.operation,&case.opened_at,&Json(&case)]).await?;
            }
            let attempt=writes.attempt;

            tx.execute("INSERT INTO shared_identity_attempts(product,operation,challenge,created_at,intent,request_digest,response) VALUES($1,$2,$3,$4,$5,$6,$7)", &[&scope.product,&attempt.intent.operation,&attempt.intent.challenge,&attempt.intent.created_at,&Json(&attempt.intent),&attempt.digest,&Json(attempt.response)]).await?;

        }
        tx.commit().await?;
Ok(response)
    }).await
    }
    async fn change(
        &self,
        scope: ChangeScope<'_>,
        decide: impl FnOnce(ChangeContext) -> Result<ChangeDecision, ServiceError> + Send,
    ) -> Result<Response, ServiceError> {
        finish(async {
        let mut db=self.db.lock().await;
let tx=db.transaction().await?;

        login_lock(&tx,scope.product,scope.login).await?;
        operation_lock(&tx,scope.product,&scope.intent.authorization.operation).await?;

        let owner=tx.query_opt("SELECT s.subject_id,s.status FROM shared_identity_product_refs r JOIN shared_identity_subjects s USING(subject_id) WHERE r.product=$1 AND r.subject_ref=$2 FOR UPDATE OF s", &[&scope.product,&scope.intent.subject_ref.as_str()]).await?.ok_or(Error::Unauthorized)?;

        let subject=SubjectId(owner.get(0));

        let enrollment=tx.query_opt("SELECT security_version,confirmed FROM shared_identity_enrollments WHERE product=$1 AND account=$2 AND subject_ref=$3 FOR UPDATE", &[&scope.product,&scope.intent.authorization.account,&scope.intent.subject_ref.as_str()]).await?.ok_or(Error::Unauthorized)?;

        let version_i64:i64=enrollment.get(0);

        let version=u64::try_from(version_i64).map_err(|_|Error::Invalid)?;

        let prior=tx.query_opt("SELECT request_digest,event FROM shared_identity_security_events WHERE product=$1 AND operation=$2", &[&scope.product,&scope.intent.authorization.operation]).await?.map(|r|(r.get(0),r.get::<_,Json<SignedSecurityEvent>>(1).0));

        let login=tx.query_opt(
            "SELECT issuer,login_subject FROM shared_identity_product_logins WHERE product=$1 AND subject_id=$2 FOR UPDATE",
            &[&scope.product,&subject.as_str()],
        ).await?.map(|row| ProductLoginIdentity::new(scope.product.into(), subject.clone(), row.get(0), row.get(1)).map_err(|_| Error::Invalid)).transpose()?;

        let (old_key,old_bank)=if version>1 {
            let event=tx.query_one("SELECT event FROM shared_identity_security_events WHERE product=$1 AND subject_ref=$2 AND security_version=$3", &[&scope.product,&scope.intent.subject_ref.as_str(),&version_i64]).await?.get::<_,Json<SignedSecurityEvent>>(0).0.event;

            (event.initial_key,event.bank_digest)
        }else{
            let intent=tx.query_one("SELECT a.intent FROM shared_identity_attempts a JOIN shared_identity_enrollments e USING(product,operation) WHERE e.product=$1 AND e.account=$2 ORDER BY a.created_at DESC LIMIT 1", &[&scope.product,&scope.intent.authorization.account]).await?.get::<_,Json<EnrollmentIntent>>(0).0;

            (intent.initial_key,intent.bank_digest)
        };

        let (response,writes)=decide(ChangeContext {version,subject,status:owner.get(1),confirmed:enrollment.get(1),login,old_key,old_bank,prior})?.into_parts();

        if let Some(writes)=writes {
            let event=&writes.event.event;
let next=i64::try_from(event.security_version).map_err(|_|Error::Invalid)?;

            tx.execute("INSERT INTO shared_identity_security_events(product,subject_ref,security_version,operation,request_digest,event) VALUES($1,$2,$3,$4,$5,$6)", &[&scope.product,&event.subject_ref.as_str(),&next,&event.id,&writes.digest.as_slice(),&Json(&writes.event)]).await?;

            if tx.execute("UPDATE shared_identity_enrollments SET security_version=$3 WHERE product=$1 AND account=$2 AND security_version=$4", &[&scope.product,&scope.intent.authorization.account,&next,&version_i64]).await?!=1 {return Err(Error::Conflict.into());
}
        }
        tx.commit().await?;
Ok(response)
    }).await
    }
}
