mod sealed {
    pub trait Sealed {}
}

/// Marker trait for [`crate::TokenSet`] validation state. Sealed — only [`Validated`] and [`Unvalidated`] implement it.
pub trait ValidationState: sealed::Sealed {}

/// Marker type: the `id_token` signature has not yet been verified.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Unvalidated;

/// Marker type: the `id_token` signature has been verified, or no `id_token` was present.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Validated;

impl sealed::Sealed for Unvalidated {}
impl sealed::Sealed for Validated {}
impl ValidationState for Unvalidated {}
impl ValidationState for Validated {}
