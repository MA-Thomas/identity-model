CREATE TABLE IF NOT EXISTS shared_identity_subjects (
 subject_id TEXT PRIMARY KEY,
 status TEXT NOT NULL CHECK (status IN ('active','disputed','superseded'))
);
CREATE TABLE IF NOT EXISTS shared_identity_logins (
 issuer TEXT NOT NULL, login_subject TEXT NOT NULL,
 subject_id TEXT NOT NULL REFERENCES shared_identity_subjects(subject_id),
 PRIMARY KEY(issuer,login_subject)
);
CREATE TABLE IF NOT EXISTS shared_identity_product_refs (
 product TEXT NOT NULL, subject_id TEXT NOT NULL REFERENCES shared_identity_subjects(subject_id),
 subject_ref TEXT NOT NULL,
 PRIMARY KEY(product,subject_id), UNIQUE(product,subject_ref)
);
CREATE TABLE IF NOT EXISTS shared_identity_enrollments (
 product TEXT NOT NULL, operation TEXT NOT NULL,
 account TEXT NOT NULL, subject_ref TEXT NOT NULL,
 confirmed BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(product,operation), UNIQUE(product,account), UNIQUE(product,subject_ref),
 FOREIGN KEY(product,subject_ref) REFERENCES shared_identity_product_refs(product,subject_ref)
);
CREATE TABLE shared_identity_attempts (
 product TEXT NOT NULL, operation TEXT NOT NULL, challenge TEXT NOT NULL,
 created_at BIGINT NOT NULL, intent JSONB NOT NULL,
 request_digest BYTEA NOT NULL CHECK(octet_length(request_digest)=32), response JSONB NOT NULL,
 PRIMARY KEY(product,operation,challenge), UNIQUE(product,operation,created_at)
);
REVOKE ALL ON shared_identity_subjects,shared_identity_logins,shared_identity_product_refs,shared_identity_enrollments,shared_identity_attempts FROM PUBLIC;

CREATE TABLE shared_identity_security_events (
 product TEXT NOT NULL, subject_ref TEXT NOT NULL, security_version BIGINT NOT NULL,
 operation TEXT NOT NULL, request_digest BYTEA NOT NULL, event JSONB NOT NULL,
 PRIMARY KEY(product,subject_ref,security_version), UNIQUE(product,operation),
 FOREIGN KEY(product,subject_ref) REFERENCES shared_identity_product_refs(product,subject_ref)
);
ALTER TABLE shared_identity_enrollments ADD COLUMN security_version BIGINT NOT NULL DEFAULT 1;
REVOKE ALL ON shared_identity_security_events FROM PUBLIC;
