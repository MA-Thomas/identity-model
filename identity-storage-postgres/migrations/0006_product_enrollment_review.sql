-- Enrollment evidence as keyed fingerprints, and review of enrollments whose evidence
-- overlaps another enrollment of the same product. Fingerprints are keyed by the
-- identity service and scoped to the product; the evidence itself is not stored.
CREATE TABLE shared_identity_evidence (
 product TEXT NOT NULL, operation TEXT NOT NULL, account TEXT NOT NULL,
 field TEXT NOT NULL CHECK (field IN ('name','date_of_birth','bank_account','address','phone')),
 fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint) = 32),
 PRIMARY KEY (product, operation, field)
);
CREATE INDEX shared_identity_evidence_match ON shared_identity_evidence(product, field, fingerprint);
-- A case is recorded as opened and never rewritten; its decision is a separate fact.
CREATE TABLE shared_identity_reviews (
 product TEXT NOT NULL, id TEXT NOT NULL, operation TEXT NOT NULL,
 opened_at BIGINT NOT NULL, opened JSONB NOT NULL,
 PRIMARY KEY (product, id), UNIQUE (product, operation)
);
CREATE TABLE shared_identity_review_decisions (
 product TEXT NOT NULL, id TEXT NOT NULL, decision JSONB NOT NULL,
 PRIMARY KEY (product, id),
 FOREIGN KEY (product, id) REFERENCES shared_identity_reviews(product, id)
);
REVOKE ALL ON shared_identity_evidence, shared_identity_reviews, shared_identity_review_decisions FROM PUBLIC;
