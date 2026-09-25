//! Development mobile/FEN HTTP representations and runtime composition.
//!
//! These workflows record evidence against host-supplied subject IDs. They do not
//! authorize product enrollment, resolve shared subjects, or implement the Phoros
//! ceremony. A future product host must resolve subject ownership through the
//! identity application before attaching ceremony evidence to that subject.
pub mod mobile;
pub mod mobile_http;
pub mod runtime;
