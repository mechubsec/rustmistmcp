//! Mist-specific models and client adapters.
//!
//! The crate boundary is established here; Task 2 adds the first public types.

pub mod catalog;
pub mod client;
pub mod execute_class;
pub mod pagination;
pub mod rate_limit;
pub mod request;

mod config;
mod grant;
mod target;

pub use catalog::{Catalog, MistAction, PaginationMode};
pub use client::{
    BlockedMistClient, HttpMistClient, HttpMistClientConfig, HttpMistClientError, MistClient,
    MistError,
};
pub use config::{ConfigError, CredentialSource, MistConfig, validate_mist_endpoint};
pub use grant::MistGrant;
pub use pagination::{
    MAX_ENCODED_CURSOR_BYTES, MistCursor, MistCursorRequestContext, MistPageInfo,
};
pub use rate_limit::{BudgetExhausted, BudgetStatus, CallPriority, RateLimitBudget};
pub use request::{MistRequest, MistResponse, MistResponseBody};
pub use target::{MistTarget, MistTargetError};
