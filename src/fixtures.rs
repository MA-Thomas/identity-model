mod fixture_labels;
mod narrative;
mod rendering;
mod summary;
mod support;

use crate::fen::*;
use crate::flows::*;
use crate::identity::*;
use crate::workflows::*;
use fixture_labels::*;
use support::{join_ids, join_strings, push_line};

pub use narrative::workflow_narrative_lines;
pub use rendering::{
    materialized_fixture_from_state, render_workflow_fixture, MaterializedFixture, WorkflowFixture,
};
use summary::fact_payload_summary;
