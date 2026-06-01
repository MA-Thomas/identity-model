CREATE TABLE IF NOT EXISTS identity_workflow_transactions (
  transaction_id TEXT PRIMARY KEY,
  transaction_kind TEXT NOT NULL CHECK (
    transaction_kind IN ('workflow_slice', 'episode_composition')
  ),
  committed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_episodes (
  append_sequence BIGINT NOT NULL UNIQUE CHECK (append_sequence >= 0),
  transaction_id TEXT NOT NULL REFERENCES identity_workflow_transactions(transaction_id),
  committed_at TEXT NOT NULL,

  episode_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  episode_kind TEXT NOT NULL,
  label TEXT NOT NULL,
  problem_code JSONB,
  status_kind TEXT NOT NULL CHECK (status_kind IN ('active', 'dormant', 'resolved')),
  status_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  onset JSONB,
  authored_by JSONB NOT NULL,
  authored_at TEXT NOT NULL,
  notes TEXT
);

CREATE INDEX IF NOT EXISTS identity_episodes_subject_append_idx
  ON identity_episodes (subject_id, append_sequence);

CREATE INDEX IF NOT EXISTS identity_episodes_kind_idx
  ON identity_episodes (episode_kind);

CREATE TABLE IF NOT EXISTS identity_episode_memberships (
  append_sequence BIGINT NOT NULL UNIQUE CHECK (append_sequence >= 0),
  transaction_id TEXT NOT NULL REFERENCES identity_workflow_transactions(transaction_id),
  committed_at TEXT NOT NULL,

  membership_id TEXT PRIMARY KEY,
  fact_id TEXT NOT NULL REFERENCES identity_facts(fact_id),
  episode_id TEXT NOT NULL REFERENCES identity_episodes(episode_id),
  role TEXT NOT NULL,
  asserted_by JSONB NOT NULL,
  asserted_kind TEXT NOT NULL CHECK (asserted_kind IN ('point', 'period')),
  asserted_start TEXT NOT NULL,
  asserted_end TEXT,
  status_kind TEXT NOT NULL CHECK (status_kind IN ('active', 'retracted')),
  status_payload JSONB NOT NULL DEFAULT '{}'::jsonb,

  CHECK (
    (asserted_kind = 'point' AND asserted_end IS NULL)
    OR
    (asserted_kind = 'period' AND asserted_end IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS identity_episode_memberships_episode_idx
  ON identity_episode_memberships (episode_id, append_sequence);

CREATE INDEX IF NOT EXISTS identity_episode_memberships_fact_idx
  ON identity_episode_memberships (fact_id, append_sequence);

CREATE TABLE IF NOT EXISTS identity_episode_relations (
  append_sequence BIGINT NOT NULL UNIQUE CHECK (append_sequence >= 0),
  transaction_id TEXT NOT NULL REFERENCES identity_workflow_transactions(transaction_id),
  committed_at TEXT NOT NULL,

  relation_id TEXT PRIMARY KEY,
  source_episode_id TEXT NOT NULL REFERENCES identity_episodes(episode_id),
  target_episode_id TEXT NOT NULL REFERENCES identity_episodes(episode_id),
  relation_type TEXT NOT NULL CHECK (relation_type IN ('part_of')),
  asserted_by JSONB NOT NULL,
  asserted_kind TEXT NOT NULL CHECK (asserted_kind IN ('point', 'period')),
  asserted_start TEXT NOT NULL,
  asserted_end TEXT,
  status_kind TEXT NOT NULL CHECK (status_kind IN ('active', 'retracted')),
  status_payload JSONB NOT NULL DEFAULT '{}'::jsonb,

  CHECK (
    (asserted_kind = 'point' AND asserted_end IS NULL)
    OR
    (asserted_kind = 'period' AND asserted_end IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS identity_episode_relations_source_idx
  ON identity_episode_relations (source_episode_id, append_sequence);

CREATE INDEX IF NOT EXISTS identity_episode_relations_target_idx
  ON identity_episode_relations (target_episode_id, append_sequence);
