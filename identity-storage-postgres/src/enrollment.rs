//! PostgreSQL implementation of the identity application's atomic ownership contracts.
use identity_application::enrollment::{ports::*, ServiceError};

use identity_contract::{changes::*, *};

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
async fn login_lock(tx: &Transaction<'_>, login: (&str, &str)) -> Result<(), StoreError> {
    let key = serde_json::to_string(&login).map_err(|_| Error::Invalid)?;

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

    if tx
        .query_opt(
            "SELECT 1 FROM shared_identity_schema_migrations WHERE version=1",
            &[],
        )
        .await?
        .is_none()
    {
        tx.batch_execute(include_str!("../migrations/0001_shared_enrollment.sql"))
            .await?;

        tx.execute(
            "INSERT INTO shared_identity_schema_migrations(version) VALUES(1)",
            &[],
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
    async fn lookup(&self, product: &str, operation: &str) -> Result<Response, ServiceError> {
        finish(async {
    let db = self.db.lock().await;

    Ok(db.query_opt("SELECT response FROM shared_identity_attempts WHERE product=$1 AND operation=$2 ORDER BY created_at DESC LIMIT 1", &[&product,&operation]).await?.map_or(Response::Missing, |r| r.get::<_,Json<Response>>(0).0))
    }).await
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

        login_lock(&tx,scope.login).await?;

        operation_lock(&tx,scope.product,&scope.intent.operation).await?;

        let prior=tx.query_opt("SELECT intent,request_digest,response FROM shared_identity_attempts WHERE product=$1 AND operation=$2 ORDER BY created_at DESC LIMIT 1", &[&scope.product,&scope.intent.operation]).await?.map(|r|PriorAttempt {intent:r.get::<_,Json<EnrollmentIntent>>(0).0,digest:r.get(1),response:r.get::<_,Json<Response>>(2).0});

        // Subject row protection also serializes product-reference creation through different logins.
        let login=if let Some(row)=tx.query_opt("SELECT s.subject_id,s.status FROM shared_identity_logins l JOIN shared_identity_subjects s USING(subject_id) WHERE l.issuer=$1 AND l.login_subject=$2 FOR UPDATE OF s", &[&scope.login.0,&scope.login.1]).await? {
            let subject:String=row.get(0);

            let product_ref=tx.query_opt("SELECT subject_ref FROM shared_identity_product_refs WHERE product=$1 AND subject_id=$2", &[&scope.product,&subject]).await?.map(|r|r.get(0));

            Some(LoginOwner {subject,status:row.get(1),product_ref})
        }else{None};

        let enrollment=tx.query_opt("SELECT account,subject_ref,confirmed FROM shared_identity_enrollments WHERE product=$1 AND operation=$2 FOR UPDATE", &[&scope.product,&scope.intent.operation]).await?.map(|r|EnrollmentOwner {account:r.get(0),subject_ref:r.get(1),confirmed:r.get(2)});

        let (response,writes)=decide(EnrollmentContext {prior,enrollment,login})?.into_parts();

        if let Some(writes)=writes {
            if let Some((subject,status))=writes.subject {tx.execute("INSERT INTO shared_identity_subjects(subject_id,status) VALUES($1,$2)", &[&subject,&status]).await?;
}
            if let Some((issuer,login,subject))=writes.login {tx.execute("INSERT INTO shared_identity_logins(issuer,login_subject,subject_id) VALUES($1,$2,$3)", &[&issuer,&login,&subject]).await?;
}
            if let Some((subject,reference))=writes.product_ref {tx.execute("INSERT INTO shared_identity_product_refs(product,subject_id,subject_ref) VALUES($1,$2,$3)", &[&scope.product,&subject,&reference]).await?;
}
            if let Some((account,reference))=writes.enrollment {tx.execute("INSERT INTO shared_identity_enrollments(product,operation,account,subject_ref) VALUES($1,$2,$3,$4)", &[&scope.product,&scope.intent.operation,&account,&reference]).await?;
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

        let mut logins=vec![scope.login];
if let Some(login)=scope.new_login{logins.push(login);
}logins.sort_unstable();
logins.dedup();

        for login in logins {login_lock(&tx,login).await?;
}
        operation_lock(&tx,scope.product,&scope.intent.authorization.operation).await?;

        let owner=tx.query_opt("SELECT s.subject_id,s.status FROM shared_identity_product_refs r JOIN shared_identity_subjects s USING(subject_id) WHERE r.product=$1 AND r.subject_ref=$2 FOR UPDATE OF s", &[&scope.product,&scope.intent.subject_ref.as_str()]).await?.ok_or(Error::Unauthorized)?;

        let subject:String=owner.get(0);

        let enrollment=tx.query_opt("SELECT security_version,confirmed FROM shared_identity_enrollments WHERE product=$1 AND account=$2 AND subject_ref=$3 FOR UPDATE", &[&scope.product,&scope.intent.authorization.account,&scope.intent.subject_ref.as_str()]).await?.ok_or(Error::Unauthorized)?;

        let version_i64:i64=enrollment.get(0);

        let version=u64::try_from(version_i64).map_err(|_|Error::Invalid)?;

        let prior=tx.query_opt("SELECT request_digest,event FROM shared_identity_security_events WHERE product=$1 AND operation=$2", &[&scope.product,&scope.intent.authorization.operation]).await?.map(|r|(r.get(0),r.get::<_,Json<SignedSecurityEvent>>(1).0));

        let login_owned=tx.query_opt("SELECT 1 FROM shared_identity_logins WHERE issuer=$1 AND login_subject=$2 AND subject_id=$3", &[&scope.login.0,&scope.login.1,&subject]).await?.is_some();

        let new_login_owner=if let Some((issuer,login))=scope.new_login {tx.query_opt("SELECT subject_id FROM shared_identity_logins WHERE issuer=$1 AND login_subject=$2", &[&issuer,&login]).await?.map(|r|r.get(0))}else{None};

        let (old_key,old_bank)=if version>1 {
            let event=tx.query_one("SELECT event FROM shared_identity_security_events WHERE product=$1 AND subject_ref=$2 AND security_version=$3", &[&scope.product,&scope.intent.subject_ref.as_str(),&version_i64]).await?.get::<_,Json<SignedSecurityEvent>>(0).0.event;

            (event.initial_key,event.bank_digest)
        }else{
            let intent=tx.query_one("SELECT a.intent FROM shared_identity_attempts a JOIN shared_identity_enrollments e USING(product,operation) WHERE e.product=$1 AND e.account=$2 ORDER BY a.created_at DESC LIMIT 1", &[&scope.product,&scope.intent.authorization.account]).await?.get::<_,Json<EnrollmentIntent>>(0).0;

            (intent.initial_key,intent.bank_digest)
        };

        let (response,writes)=decide(ChangeContext {version,subject,status:owner.get(1),confirmed:enrollment.get(1),login_owned,new_login_owner,old_key,old_bank,prior})?.into_parts();

        if let Some(writes)=writes {
            if let Some((issuer,login,subject))=writes.login {tx.execute("INSERT INTO shared_identity_logins(issuer,login_subject,subject_id) VALUES($1,$2,$3)", &[&issuer,&login,&subject]).await?;
}
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
