//! Journal sealed values safely in [Restate](https://restate.dev) handlers.
//!
//! Restate journals every step of a handler and replays the journal after a
//! failure or suspension, comparing what the handler does again with what it
//! recorded. Sealing draws a fresh nonce, so it is not deterministic: a value
//! sealed outside a journaled action seals to other bytes on replay, and a
//! `ctx.set` or call that carries it no longer matches its journal entry.
//!
//! This module seals inside `ctx.run`, so Restate journals the sealed bytes
//! once and replays them:
//!
//! - [`seal`] seals a value the handler already holds, such as its input.
//! - [`seal_with`] fetches and seals inside one `run`, so the plaintext is
//!   never a `run` result and never reaches the journal.
//! - [`seal_record`] and [`seal_record_with`] do the same for a whole
//!   [`Record`].
//!
//! [`Sealed<F>`](Sealed) and [`BlindIndex<S>`](crate::BlindIndex) implement
//! Restate's `Serialize`, `Deserialize`, and `PayloadMetadata` as
//! `application/octet-stream` without a schema, so they can be kept in state,
//! passed in calls, awakeables, and promises, and returned. The codec moves
//! bytes; it never encrypts. Opening is deterministic, so it needs no `run`:
//! open where the plaintext is used, and never return it from a `run`.
//!
//! [`handler_error`] maps an [`Error`] to a Restate error: faults of the data
//! or the request are terminal, and faults of the environment are retried.
//! [`ObjectKey`] encodes a binding's index arguments as a Virtual Object key
//! and parses them back strictly.
//!
//! Journal entries are plaintext to Restate unless the handler sealed them.
//! Ingress input in particular arrives as the caller sent it. See the
//! [Restate guide] for what each journal entry exposes and the org-shredding
//! runbook.
//!
//! ```no_run
//! use cryptbox::{
//!     EncryptionKeyring, Seal, SealId, Padding, Tenant, Utf8,
//!     restate::{self, ObjectKey},
//! };
//! use restate_sdk::prelude::*;
//!
//! struct CustomerEmail;
//!
//! impl Seal for CustomerEmail {
//!     const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
//!     const PADDING: Padding = Padding::NONE;
//!     const RECORD: bool = false;
//!     type Value = String;
//!     type Codec = Utf8;
//!     type Binding = Tenant;
//!     type Indexes = ();
//! }
//!
//! # async fn load_email() -> HandlerResult<String> { unimplemented!() }
//! /// Keyed by its tenant: one object per tenant.
//! struct Customer {
//!     keys: EncryptionKeyring,
//! }
//!
//! #[restate_sdk::object]
//! impl Customer {
//!     #[handler]
//!     async fn import(&self, ctx: ObjectContext<'_>) -> HandlerResult<()> {
//!         let tenant = ObjectKey::<Tenant>::parse(ctx.key()).map_err(restate::handler_error)?;
//!
//!         // Fetched and sealed in one `run`: the journal holds only the envelope.
//!         let email = restate::seal_with::<CustomerEmail, _>(&ctx, load_email, &tenant, &self.keys)
//!             .name("seal-email")
//!             .await?;
//!         ctx.set("email", email);
//!
//!         Ok(())
//!     }
//! }
//! ```
//!
#![doc = concat!(
    "[Restate guide]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/restate.md",
)]

use std::future::Future;

use restate_sdk::{
    context::{
        Context, ObjectContext, RunClosure, RunFuture, SharedObjectContext, SharedWorkflowContext,
        WorkflowContext,
    },
    errors::{HandlerError, HandlerResult, TerminalError},
    serde::Json,
};

use crate::{
    Args, BlindIndexKeySource, EncryptionKeySource, Error, Record, Seal, Sealed, binding::domain,
};

mod codec;
mod object_key;

pub use object_key::ObjectKey;

/// A Restate handler context that runs journaled actions: [`Context`],
/// [`ObjectContext`], [`SharedObjectContext`], [`WorkflowContext`], or
/// [`SharedWorkflowContext`].
///
/// The sealing functions take any of them. Unlike Restate's own
/// `ContextSideEffects<'ctx>`, this trait names no lifetime, so a handler can
/// pass values it borrows for less than the whole invocation. The handler's
/// future stays `Send`, as Restate requires.
///
/// This trait is sealed: the contexts above are its only implementations.
pub trait RunContext: private::Run {}

impl<C: private::Run> RunContext for C {}

mod private {
    use super::{
        Context, ObjectContext, RunClosure, RunFuture, SharedObjectContext, SharedWorkflowContext,
        TerminalError, WorkflowContext,
    };
    use restate_sdk::{
        context::ContextSideEffects,
        serde::{Deserialize, Serialize},
    };

    pub trait Run {
        /// Runs `closure` as a journaled action whose borrows last `'a`.
        fn run_for<'a, R, T>(&'a self, closure: R) -> impl RunFuture<Result<T, TerminalError>> + 'a
        where
            R: RunClosure<Output = T> + Send + 'a,
            R::Fut: Send + 'a,
            T: Serialize + Deserialize + 'static;
    }

    macro_rules! run {
        ($($context:ident),*) => {$(
            impl Run for $context<'_> {
                fn run_for<'a, R, T>(
                    &'a self,
                    closure: R,
                ) -> impl RunFuture<Result<T, TerminalError>> + 'a
                where
                    R: RunClosure<Output = T> + Send + 'a,
                    R::Fut: Send + 'a,
                    T: Serialize + Deserialize + 'static,
                {
                    // Contexts are covariant: shorten the context to the borrows.
                    let context: &'a $context<'a> = self;
                    context.run(closure)
                }
            }
        )*};
    }

    run!(
        Context,
        ObjectContext,
        SharedObjectContext,
        WorkflowContext,
        SharedWorkflowContext
    );
}

/// Seals `value` inside `ctx.run`, so Restate journals the sealed bytes and
/// replays them.
///
/// Use it for a value the handler already holds, such as a field of its
/// input. The context, value, arguments, and keys share one lifetime, and
/// move into the `run` closure. The key source is a trait object, so a source
/// that borrows, such as an `Arc<dyn EncryptionKeySource>`, keeps the handler's
/// future `Send`. The returned future is Restate's
/// own: name it or give it a retry policy before awaiting it.
///
/// # Errors
///
/// The future fails with a [`TerminalError`] once sealing fails with a
/// terminal error, or once Restate stops retrying a retryable one; see
/// [`handler_error`].
pub fn seal<'a, F>(
    ctx: &'a impl RunContext,
    value: &'a F::Value,
    args: impl Args<F>,
    keys: &'a dyn EncryptionKeySource,
) -> impl RunFuture<Result<Sealed<F>, TerminalError>> + 'a
where
    F: Seal,
    F::Value: Sync,
{
    // Resolved before the `run`, so the future holds no borrow of `args`.
    let domain = domain(args);

    ctx.run_for(move || async move {
        Sealed::seal_in(value, &domain.map_err(handler_error)?, keys).map_err(handler_error)
    })
}

/// Fetches a value and seals it inside one `ctx.run`.
///
/// `fetch` runs only when the action runs, not on replay, and its plaintext
/// never leaves the `run`: Restate journals only the sealed bytes. Use it for a
/// value loaded from another system, such as a database or an API. `fetch` owns
/// what it uses: move a clone or an `Arc` of a database handle into it.
///
/// # Errors
///
/// The future fails with a [`TerminalError`] when `fetch` or sealing fails
/// with a terminal error, or once Restate stops retrying a retryable one.
/// Errors of `fetch` are classified as `fetch` returns them.
pub fn seal_with<'a, F, Fut>(
    ctx: &'a impl RunContext,
    fetch: impl FnOnce() -> Fut + Send + 'static,
    args: impl Args<F>,
    keys: &'a dyn EncryptionKeySource,
) -> impl RunFuture<Result<Sealed<F>, TerminalError>> + 'a
where
    F: Seal,
    Fut: Future<Output = HandlerResult<F::Value>> + Send + 'static,
{
    let domain = domain(args);

    ctx.run_for(move || async move {
        let value = fetch().await?;
        Sealed::seal_in(&value, &domain.map_err(handler_error)?, keys).map_err(handler_error)
    })
}

/// Seals a whole [`Record`] inside `ctx.run`, as [`seal`] does for one value.
///
/// Restate journals the sealed record through [`Json`], so its sealed struct
/// needs Serde's traits: with `#[derive(Record)]`, add
/// `attr(derive(serde::Serialize, serde::Deserialize))`. Its plaintext
/// fields, such as the record ID, are journaled as they are.
///
/// # Errors
///
/// As [`seal`].
pub fn seal_record<'a, R>(
    ctx: &'a impl RunContext,
    record: &'a R,
    binding: &'a R::Binding,
    keys: &'a (impl EncryptionKeySource + BlindIndexKeySource + ?Sized),
) -> impl RunFuture<Result<Json<R::Sealed>, TerminalError>> + 'a
where
    R: Record + Sync,
    R::Sealed: serde::Serialize + serde::de::DeserializeOwned + 'static,
{
    ctx.run_for(move || async move { record.seal(binding, keys).map(Json).map_err(handler_error) })
}

/// Fetches a [`Record`] and seals it inside one `ctx.run`, as [`seal_with`]
/// does for one value.
///
/// # Errors
///
/// As [`seal_with`].
pub fn seal_record_with<'a, R, Fut>(
    ctx: &'a impl RunContext,
    fetch: impl FnOnce() -> Fut + Send + 'static,
    binding: &'a R::Binding,
    keys: &'a (impl EncryptionKeySource + BlindIndexKeySource + ?Sized),
) -> impl RunFuture<Result<Json<R::Sealed>, TerminalError>> + 'a
where
    R: Record,
    R::Sealed: serde::Serialize + serde::de::DeserializeOwned + 'static,
    Fut: Future<Output = HandlerResult<R>> + Send + 'static,
{
    ctx.run_for(move || async move {
        let record = fetch().await?;
        record.seal(binding, keys).map(Json).map_err(handler_error)
    })
}

/// Maps an error to a Restate handler error: terminal, or retried.
///
/// Faults of the data or the request are terminal, since retrying the same
/// input can never succeed: a failed authentication, a binding mismatch, a
/// codec failure, a key the keyring does not hold, a malformed envelope, or an
/// invalid binding or [object key](ObjectKey). Faults of the environment are
/// retried, since loading keys, restoring configuration, or deploying a fix
/// resolves them: unavailable keys, missing or invalid key configuration,
/// unavailable randomness, and internal errors. See [`is_retryable`].
///
/// A terminal error carries the error's sanitized message, and code 400 for an
/// invalid object key or 500 otherwise.
///
/// Opening needs no `run`, so use it where the handler opens a value:
/// `sealed.open(&tenant, &keys).map_err(restate::handler_error)?`.
#[must_use]
pub fn handler_error(error: Error) -> HandlerError {
    if is_retryable(&error) {
        return error.into();
    }

    let code = match error {
        Error::InvalidObjectKey => 400,
        _ => 500,
    };
    TerminalError::new_with_code(code, error.to_string()).into()
}

/// Reports whether Restate should retry after `error`, as [`handler_error`]
/// classifies it.
#[must_use]
pub fn is_retryable(error: &Error) -> bool {
    match error {
        // The environment: keys, configuration, randomness, and the code itself.
        Error::KeysUnavailable
        | Error::KeysNotInstalled
        | Error::BlindIndexKeysNotConfigured
        | Error::DuplicateEncryptionKey(_)
        | Error::DuplicateBlindIndexKey(_)
        | Error::InvalidKeyEncoding
        | Error::RandomnessUnavailable
        | Error::Internal
        | Error::DuplicatePreparedIndex(_)
        | Error::BlindIndexNotPrepared(_) => true,
        #[cfg(feature = "migrate")]
        Error::IndexColumnMismatch { .. } => true,
        // The data or the request.
        Error::NotCiphertext
        | Error::InvalidEnvelope
        | Error::UnsupportedFormatVersion(_)
        | Error::UnsupportedSuite(_)
        | Error::UnknownEncryptionKey(_)
        | Error::UnknownBlindIndexKey(_)
        | Error::AuthenticationFailed
        | Error::BindingMismatch
        | Error::CodecFailed(_)
        | Error::BlindIndexNormalizationFailed
        | Error::MessageTooLong
        | Error::PaddingOverflow
        | Error::InvalidPadding
        | Error::InvalidBinding
        | Error::InvalidBlindIndex
        | Error::InvalidObjectKey => false,
        #[cfg(feature = "migrate")]
        Error::LegacyRecoveryFailed(_) => false,
    }
}
