//! Re-export [`FlowKey`] from the shared [`crate::flow`] module.
//!
//! The canonical definition lives in `src/flow.rs` so that `pcap` can use it
//! without depending on `stats`.

pub use crate::flow::FlowKey;
