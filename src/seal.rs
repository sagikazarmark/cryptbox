use crate::id::identifier;
use crate::{BoundList, Codec, IndexList, Padding, RecordIdType};

identifier!(SealId, "A stable seal identifier.");

/// Declares how values are sealed: their identity, value type, codec,
/// padding, binding, and blind indexes.
///
/// A seal is either a marker over a separate value type or its own value
/// (`type Value = Self`). A value type (`String`, `Address`, `Secret<String>`)
/// says how it encodes; the seal gives its values an identity. One value type
/// can back several markers, such as `HomeAddress` and `BillingAddress` over one
/// `Address`, and each seal has its own ID so their sealed values cannot be
/// swapped. A seal is not tied to storage: its values may be database columns,
/// messages, or whole responses. A marker and a self-valued seal with the same
/// ID and codec read each other's values.
///
/// Every sealed value is bound at runtime to its seal ID, to the values of the
/// seal's [bound ID types](Self::Bound), such as a tenant, and, when it binds a
/// [record](Self::Record), to the ID of the record it is stored in. Opening it as
/// another seal, or under other bound values or another record, fails
/// authentication. The binding arguments of each call are
/// typed by the seal; see [`Args`](crate::Args).
///
/// Generate a unique ID for each seal, keep it stable across Rust and database
/// renames, and never reuse it for a different seal. Changing the ID makes
/// existing values fail authentication. Declaring the same ID on several types
/// deliberately makes them the same seal.
///
/// The value type, codec representation, seal ID, and binding declaration define
/// persistent schema. The envelope does not store a codec identifier, so
/// incompatible changes require an explicit data migration. Padding is write
/// policy instead: the envelope records whether a value is padded. See
/// [`crate::schema`] and [`crate::testing`] for CI checks of the codec and IDs;
/// an envelope written with another binding declaration reports
/// [`Error::BindingMismatch`](crate::Error::BindingMismatch) when opened.
///
/// For blind indexes, the seal domain-separates derivation; it does not
/// authenticate the stored index representation. Compare decrypted candidate
/// plaintext for lookup, and recompute indexes separately when stored-index
/// consistency is required.
///
/// # Examples
///
/// ```
/// use cryptbox::{Padding, Seal, SealId, Utf8};
///
/// /// Primary contact address.
/// pub struct UserEmail;
///
/// impl Seal for UserEmail {
///     const ID: SealId = cryptbox::seal_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = Utf8;
///     type Bound = ();
///     type Record = ();
///     type Indexes = ();
/// }
/// ```
///
/// With the `derive` feature, `#[derive(Seal)]` writes this impl from
/// `#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]`,
/// taking `String`'s built-in default codec, `Utf8`.
/// Add `bound(TenantId)`, `record = i64`, or `indexes(EmailLookup)` to set
/// [`Self::Bound`], [`Self::Record`], or [`Self::Indexes`]. On a type with
/// fields, the derive makes the type its own value: `codec = Json` encodes it
/// whole, and `transparent` stores its single field.
///
/// A hand-written impl always names its codec. Only a derived seal over `String`,
/// `Vec<u8>`, or their [`Secret`](crate::Secret) wrappers may omit it, taking
/// [`Utf8`](crate::Utf8) or [`Raw`](crate::Raw); every other value type names
/// its codec, so no other crate can choose or change it.
///
/// See the [custom-field example] and [ownership reference].
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a seal",
    label = "not a seal",
    note = "declare one with `#[derive(cryptbox::Seal)]`; in a `#[derive(Record)]`, mark a field `#[cryptbox(seal = \"<uuid>\")]`"
)]
pub trait Seal: 'static {
    /// The stable identifier, independent of Rust and database names.
    const ID: SealId;

    /// The padding policy applied to new values between the codec and encryption.
    ///
    /// This describes how values are written, not how they are read: the
    /// envelope records whether its payload is padded. Changing the policy keeps
    /// stored values readable, and resealing rewrites them with it; see
    /// [`Padding`].
    const PADDING: Padding;

    /// The plaintext application type of this seal's values.
    type Value;

    /// The codec used before encryption and after decryption.
    ///
    /// Its byte representation must remain compatible with stored values.
    /// A derived seal over `String`, `Vec<u8>`, or their `Secret` wrappers
    /// defaults to [`Utf8`](crate::Utf8) or [`Raw`](crate::Raw).
    type Codec: Codec<Self::Value>;

    /// The bound ID types every value is bound to, such as `(OrgId, WorkspaceId)`,
    /// or `()` for none: a [`BoundList`].
    ///
    /// Their kinds are persistent schema; their values are supplied at each call,
    /// in this order. Which keys protect a value is the caller's choice: with a
    /// keyring per tenant, destroying one tenant's root keys shreds that tenant's
    /// values alone.
    type Bound: BoundList;

    /// The type of the ID of the record every value is stored in and bound to,
    /// such as `i64`, or `()` for none: a [`RecordIdType`].
    type Record: RecordIdType;

    /// The blind indexes declared over this seal, as a tuple of
    /// [`BlindIndexSpec`](crate::BlindIndexSpec)s, or `()` for none.
    ///
    /// Declaring them lets storage helpers reject a seal whose blind indexes
    /// they would not write, such as the automatic column
    /// [`Plain`](crate::Plain). See [`IndexList`].
    type Indexes: IndexList<Self>;
}

/// Creates a [`SealId`](crate::SealId) from a UUID literal.
#[macro_export]
macro_rules! seal_id {
    ($value:literal) => {{
        const ID: $crate::SealId =
            $crate::SealId::from_bytes($crate::__private::uuid::uuid!($value).into_bytes());
        ID
    }};
}
