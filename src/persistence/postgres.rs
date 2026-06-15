//! PostgreSQL adapter for the FEN identity model, split by stored entity and
//! concern. Move-only decomposition of the former single-file module; the
//! public API is unchanged (everything is re-exported below).

use super::*;
#[allow(unused_imports)]
use crate::device::*;
#[allow(unused_imports)]
use crate::liveness::*;

mod app_attest;
mod challenges;
mod episodes;
mod facade;
mod facts;
mod labels;
mod migrations;
mod rows;
mod support;
mod types;
mod workflow_tx;

#[cfg(feature = "postgres-adapter")]
pub use app_attest::*;
#[cfg(feature = "postgres-adapter")]
pub use challenges::*;
#[cfg(feature = "postgres-adapter")]
pub use facade::*;
#[cfg(feature = "postgres-adapter")]
pub use facts::*;
pub use migrations::*;
pub use rows::*;
pub use types::*;

#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
pub(super) use episodes::*;
#[allow(unused_imports)]
pub(super) use labels::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
pub(super) use support::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
pub(super) use workflow_tx::*;
