//! Atomic append and durable audit adapters for application-owned workflows.
use super::*;
use identity_application::workflows::{EncryptedWorkflowStore, WorkflowAppendError};
impl EncryptedWorkflowStore for SqlxPostgresEncryptedFactRepository {
    type Error = PostgresAdapterError;
    async fn append_slice(
        &self,
        prepare: impl FnOnce(
            EncryptedWorkflowAppendSequenceState,
        ) -> Result<StoredIdentityWorkflowSlice, FactEncryptionError>,
    ) -> Result<StoredIdentityWorkflowSlice, WorkflowAppendError<Self::Error>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(sqlx_error)
            .map_err(WorkflowAppendError::Storage)?;
        acquire_workflow_sequence_lock(&mut tx)
            .await
            .map_err(WorkflowAppendError::Storage)?;
        let sequence = next_workflow_sequence_state(&mut tx)
            .await
            .map_err(WorkflowAppendError::Storage)?;
        let stored = prepare(sequence)?;
        insert_stored_workflow_slice_rows(&mut tx, &stored)
            .await
            .map_err(WorkflowAppendError::Storage)?;
        tx.commit()
            .await
            .map_err(sqlx_error)
            .map_err(WorkflowAppendError::Storage)?;
        Ok(stored)
    }
    async fn append_composition(
        &self,
        prepare: impl FnOnce(
            EncryptedWorkflowAppendSequenceState,
        ) -> Result<StoredEpisodeComposition, FactEncryptionError>,
    ) -> Result<StoredEpisodeComposition, WorkflowAppendError<Self::Error>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(sqlx_error)
            .map_err(WorkflowAppendError::Storage)?;
        acquire_workflow_sequence_lock(&mut tx)
            .await
            .map_err(WorkflowAppendError::Storage)?;
        let sequence = next_workflow_sequence_state(&mut tx)
            .await
            .map_err(WorkflowAppendError::Storage)?;
        let stored = prepare(sequence)?;
        insert_stored_episode_composition_rows(&mut tx, &stored)
            .await
            .map_err(WorkflowAppendError::Storage)?;
        tx.commit()
            .await
            .map_err(sqlx_error)
            .map_err(WorkflowAppendError::Storage)?;
        Ok(stored)
    }
    async fn encrypted_facts(
        &self,
        subject: &SubjectId,
    ) -> Result<Vec<StoredEncryptedFact>, Self::Error> {
        self.encrypted_facts_for_subject(subject).await
    }
    async fn audit(&self, event: &FactMaterializationAuditEvent) -> Result<(), Self::Error> {
        self.record_materialization_audit_event(event).await
    }
}
