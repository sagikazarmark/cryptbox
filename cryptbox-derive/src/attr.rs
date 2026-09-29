//! Parses the shared `#[cryptbox(...)]` attribute namespace.

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::{ToTokens, quote_spanned};
use syn::{
    Attribute, Ident, LitInt, LitStr, Meta, Path, Token, Type, meta::ParseNestedMeta,
    parenthesized, parse::ParseStream, punctuated::Punctuated, spanned::Spanned,
};

/// Every key of the namespace. Each derive accepts a subset.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Key {
    Crate,
    Id,
    Value,
    Codec,
    Padding,
    Seal,
    Bits,
    Query,
    Normalize,
    Normalizer,
    Project,
    Scope,
    Record,
    Indexes,
    IndexArgs,
    Part,
    Keys,
    Index,
    RecordId,
    Sealed,
    Attr,
    IndexColumns,
    Plaintext,
    Transparent,
}

impl Key {
    const ALL: [Self; 24] = [
        Self::Crate,
        Self::Id,
        Self::Value,
        Self::Codec,
        Self::Padding,
        Self::Seal,
        Self::Bits,
        Self::Query,
        Self::Normalize,
        Self::Normalizer,
        Self::Project,
        Self::Scope,
        Self::Record,
        Self::Indexes,
        Self::IndexArgs,
        Self::Part,
        Self::Keys,
        Self::Index,
        Self::RecordId,
        Self::Sealed,
        Self::Attr,
        Self::IndexColumns,
        Self::Plaintext,
        Self::Transparent,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Crate => "crate",
            Self::Id => "id",
            Self::Value => "value",
            Self::Codec => "codec",
            Self::Padding => "padding",
            Self::Seal => "seal",
            Self::Bits => "bits",
            Self::Query => "query",
            Self::Normalize => "normalize",
            Self::Normalizer => "normalizer",
            Self::Project => "project",
            Self::Scope => "scope",
            // `RecordId` and `IndexColumns` reuse these names in `#[derive(Record)]`.
            Self::Record | Self::RecordId => "record",
            Self::Indexes => "indexes",
            Self::IndexArgs => "index_args",
            Self::Part => "part",
            Self::Keys => "keys",
            Self::Index | Self::IndexColumns => "index",
            Self::Sealed => "sealed",
            Self::Attr => "attr",
            Self::Plaintext => "plaintext",
            Self::Transparent => "transparent",
        }
    }

    /// Whether the key stands alone, without a value.
    fn is_flag(self) -> bool {
        matches!(
            self,
            Self::Record | Self::Keys | Self::Index | Self::Plaintext | Self::Transparent
        )
    }
}

/// A validated UUID literal, kept with its span for diagnostics.
pub(crate) struct UuidLiteral {
    value: u128,
    span: Span,
}

impl UuidLiteral {
    pub(crate) fn value(&self) -> u128 {
        self.value
    }

    pub(crate) fn span(&self) -> Span {
        self.span
    }
}

impl ToTokens for UuidLiteral {
    /// Emits a hex literal grouped like the UUID, so expansions stay recognizable.
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let hex = format!("{:032x}", self.value);
        let grouped = format!(
            "0x{}_{}_{}_{}_{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32],
        );
        LitInt::new(&grouped, self.span).to_tokens(tokens);
    }
}

/// A padding policy validated at expansion.
///
/// `Padding::block` and `Padding::length` reject bad parameters only during
/// constant evaluation, which for an associated const happens after
/// monomorphization. Validating here points the error at the literal.
pub(crate) enum Padding {
    None(Span),
    Block(LitInt),
    Length(LitInt),
}

impl Padding {
    pub(crate) fn to_tokens(&self, krate: &Path) -> TokenStream {
        match self {
            Self::None(span) => quote_spanned!(*span=> #krate::Padding::NONE),
            Self::Block(size) => quote_spanned!(size.span()=> #krate::Padding::block(#size)),
            Self::Length(len) => quote_spanned!(len.span()=> #krate::Padding::length(#len)),
        }
    }
}

/// The parsed contents of every `#[cryptbox(...)]` attribute on one item.
#[derive(Default)]
pub(crate) struct Attrs {
    pub(crate) krate: Option<Path>,
    pub(crate) id: Option<UuidLiteral>,
    pub(crate) value: Option<Type>,
    pub(crate) codec: Option<Type>,
    pub(crate) padding: Option<Padding>,
    pub(crate) seal: Option<Type>,
    /// A bare `seal`, without `= Type`.
    pub(crate) seal_own: Option<Span>,
    pub(crate) bits: Option<LitInt>,
    pub(crate) query: Option<Type>,
    pub(crate) normalize: Option<Path>,
    pub(crate) normalizer: Option<LitStr>,
    pub(crate) project: Option<Path>,
    pub(crate) scope: Option<Type>,
    pub(crate) record: Option<Span>,
    pub(crate) indexes: Option<Vec<Type>>,
    pub(crate) index_args: Option<Ident>,
    pub(crate) part: Option<UuidLiteral>,
    pub(crate) keys: Option<Span>,
    pub(crate) index: Option<Span>,
    pub(crate) record_id: Option<Ident>,
    pub(crate) sealed: Option<Ident>,
    pub(crate) attr: Option<Vec<Meta>>,
    pub(crate) index_columns: Option<Vec<IndexColumn>>,
    pub(crate) plaintext: Option<Span>,
    pub(crate) transparent: Option<Span>,
    seen: Vec<Key>,
}

impl Attrs {
    /// Parses every `#[cryptbox(...)]` attribute, accepting only `keys`.
    ///
    /// Collects every error it can recover from instead of stopping at the first.
    pub(crate) fn parse(attrs: &[Attribute], keys: &[Key], errors: &mut Errors) -> Self {
        Self::parse_rejecting(attrs, keys, &[], errors)
    }

    /// Parses like [`Self::parse`], reporting each `rejected` key with its own
    /// message instead of as unknown.
    pub(crate) fn parse_rejecting(
        attrs: &[Attribute],
        keys: &[Key],
        rejected: &[(Key, &str)],
        errors: &mut Errors,
    ) -> Self {
        let mut parsed = Self::default();

        for attr in attrs.iter().filter(|attr| attr.path().is_ident("cryptbox")) {
            let result = attr.parse_nested_meta(|meta| {
                if let Some((key, message)) = rejected
                    .iter()
                    .find(|(key, _)| meta.path.is_ident(key.name()))
                {
                    parsed.seen.push(*key);
                    errors.push(syn::Error::new_spanned(&meta.path, message));
                    return skip_value(meta.input);
                }

                // Two keys can share a name, so look only among the accepted ones.
                let Some(key) = Key::ALL
                    .into_iter()
                    .filter(|key| keys.contains(key))
                    .find(|key| meta.path.is_ident(key.name()))
                else {
                    errors.push(syn::Error::new_spanned(
                        &meta.path,
                        format!(
                            "unknown `cryptbox` key `{}`; expected one of {}",
                            meta.path.to_token_stream(),
                            key_list(keys),
                        ),
                    ));
                    return skip_value(meta.input);
                };

                if parsed.seen.contains(&key) {
                    errors.push(syn::Error::new_spanned(
                        &meta.path,
                        format!("duplicate `cryptbox` key `{}`", key.name()),
                    ));
                    return skip_value(meta.input);
                }
                parsed.seen.push(key);

                let result = if key.is_flag() {
                    parsed.parse_flag(key, &meta)
                } else if key == Key::Indexes {
                    parse_indexes(meta.input).map(|list| parsed.indexes = Some(list))
                } else if key == Key::IndexColumns {
                    parse_index_columns(meta.input).map(|list| parsed.index_columns = Some(list))
                } else if key == Key::Attr {
                    parse_attr(meta.input).map(|list| parsed.attr = Some(list))
                } else if key == Key::Seal && (meta.input.is_empty() || meta.input.peek(Token![,]))
                {
                    // Each derive decides whether a bare `seal` means anything.
                    parsed.seal_own = Some(meta.path.span());
                    Ok(())
                } else {
                    meta.value()
                        .and_then(|input| parsed.parse_value(key, input))
                };
                if let Err(error) = result {
                    errors.push(error);
                    return skip_value(meta.input);
                }

                Ok(())
            });

            if let Err(error) = result {
                errors.push(error);
            }
        }

        parsed
    }

    fn parse_value(&mut self, key: Key, input: ParseStream) -> syn::Result<()> {
        match key {
            Key::Crate => {
                let path: LitStr = input.parse()?;
                self.krate = Some(path.parse()?);
            }
            Key::Id => self.id = Some(parse_uuid(key, input)?),
            Key::Part => self.part = Some(parse_uuid(key, input)?),
            Key::Value => self.value = Some(input.parse()?),
            Key::Codec => self.codec = Some(input.parse()?),
            Key::Padding => self.padding = Some(parse_padding(input)?),
            Key::Seal => self.seal = Some(input.parse()?),
            Key::Bits => self.bits = Some(parse_bits(input)?),
            Key::Query => self.query = Some(input.parse()?),
            Key::Normalize => self.normalize = Some(input.parse()?),
            Key::Normalizer => self.normalizer = Some(input.parse()?),
            Key::Project => self.project = Some(input.parse()?),
            Key::Scope => self.scope = Some(input.parse()?),
            Key::IndexArgs => self.index_args = Some(input.parse()?),
            Key::RecordId => self.record_id = Some(input.parse()?),
            Key::Sealed => self.sealed = Some(input.parse()?),
            Key::Record
            | Key::Keys
            | Key::Index
            | Key::Plaintext
            | Key::Transparent
            | Key::Indexes
            | Key::IndexColumns
            | Key::Attr => {
                unreachable!("flags and lists have no `= value`")
            }
        }

        Ok(())
    }

    fn parse_flag(&mut self, key: Key, meta: &ParseNestedMeta) -> syn::Result<()> {
        if !meta.input.is_empty() && !meta.input.peek(Token![,]) {
            return Err(meta.error(format!("`{}` takes no value", key.name())));
        }

        let span = meta.path.span();
        match key {
            Key::Record => self.record = Some(span),
            Key::Keys => self.keys = Some(span),
            Key::Index => self.index = Some(span),
            Key::Plaintext => self.plaintext = Some(span),
            Key::Transparent => self.transparent = Some(span),
            _ => unreachable!("only flags are parsed here"),
        }

        Ok(())
    }

    /// Whether `key` appeared, even when its value was invalid and already reported.
    pub(crate) fn seen(&self, key: Key) -> bool {
        self.seen.contains(&key)
    }

    /// The path generated code uses to name `cryptbox`.
    pub(crate) fn krate(&self) -> Path {
        self.krate
            .clone()
            .unwrap_or_else(|| syn::parse_quote!(::cryptbox))
    }
}

/// Returns a required value, reporting it as missing unless its key was already reported.
pub(crate) fn required<T>(
    value: Option<T>,
    attrs: &Attrs,
    key: Key,
    item: &Ident,
    example: &str,
    errors: &mut Errors,
) -> Option<T> {
    if value.is_none() && !attrs.seen(key) {
        errors.push(syn::Error::new(
            item.span(),
            format!(
                "missing `{name}`: add `#[cryptbox({name} = {example})]`",
                name = key.name()
            ),
        ));
    }

    value
}

/// Accumulates independent errors so one expansion reports all of them.
#[derive(Default)]
pub(crate) struct Errors(Option<syn::Error>);

impl Errors {
    pub(crate) fn push(&mut self, error: syn::Error) {
        match &mut self.0 {
            Some(errors) => errors.combine(error),
            None => self.0 = Some(error),
        }
    }

    pub(crate) fn finish(self) -> syn::Result<()> {
        self.0.map_or(Ok(()), Err)
    }

    /// Stops at the errors so far, or keeps accumulating when there are none.
    pub(crate) fn check(self) -> syn::Result<Self> {
        self.finish().map(|()| Self::default())
    }
}

fn key_list(keys: &[Key]) -> String {
    keys.iter()
        .map(|key| format!("`{}`", key.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Consumes the rest of one `key = value` entry, up to the next comma.
fn skip_value(input: ParseStream) -> syn::Result<()> {
    while !input.is_empty() && !input.peek(Token![,]) {
        input.parse::<TokenTree>()?;
    }

    Ok(())
}

/// Parses `indexes(A, B, …)`: at least one blind index.
fn parse_indexes(input: ParseStream) -> syn::Result<Vec<Type>> {
    let content;
    let parens = parenthesized!(content in input);
    let list = Punctuated::<Type, Token![,]>::parse_terminated(&content)?;
    if list.is_empty() {
        return Err(syn::Error::new(
            parens.span.join(),
            "list at least one blind index, or omit `indexes`",
        ));
    }

    Ok(list.into_iter().collect())
}

/// A blind index a record field writes, and the sealed struct's field that stores it.
pub(crate) struct IndexColumn {
    pub(crate) spec: Type,
    pub(crate) column: Ident,
}

impl syn::parse::Parse for IndexColumn {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let spec = input.parse()?;
        input.parse::<Token![as]>()?;
        let column = input.parse()?;

        Ok(Self { spec, column })
    }
}

/// Parses `index(A as a, B as b, …)`: at least one blind index and its column.
fn parse_index_columns(input: ParseStream) -> syn::Result<Vec<IndexColumn>> {
    let content;
    let parens = parenthesized!(content in input);
    let list = Punctuated::<IndexColumn, Token![,]>::parse_terminated(&content)?;
    if list.is_empty() {
        return Err(syn::Error::new(
            parens.span.join(),
            "list at least one `Index as column`, or omit `index`",
        ));
    }

    Ok(list.into_iter().collect())
}

/// Parses `attr(…)`: attributes for a generated item, without their `#[…]`.
fn parse_attr(input: ParseStream) -> syn::Result<Vec<Meta>> {
    let content;
    parenthesized!(content in input);
    let list = Punctuated::<Meta, Token![,]>::parse_terminated(&content)?;

    Ok(list.into_iter().collect())
}

fn parse_uuid(key: Key, input: ParseStream) -> syn::Result<UuidLiteral> {
    let name = key.name();
    if !input.peek(LitStr) {
        let mut tokens = TokenStream::new();
        while !input.is_empty() && !input.peek(Token![,]) {
            tokens.extend([input.parse::<TokenTree>()?]);
        }

        return Err(syn::Error::new_spanned(
            tokens,
            format!(
                "`{name}` must be a UUID string literal, such as \"0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64\""
            ),
        ));
    }

    let literal: LitStr = input.parse()?;
    let value = uuid_value(&literal.value()).ok_or_else(|| {
        syn::Error::new(
            literal.span(),
            format!(
                "`{name}` must be a hyphenated UUID, such as \"0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64\""
            ),
        )
    })?;

    Ok(UuidLiteral {
        value,
        span: literal.span(),
    })
}

/// Parses the hyphenated form `cryptbox::SealId::from_str` accepts.
fn uuid_value(text: &str) -> Option<u128> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return None;
    }

    let mut value = 0_u128;
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return None;
            }
        } else {
            let digit = char::from(*byte).to_digit(16)?;
            value = (value << 4) | u128::from(digit);
        }
    }

    Some(value)
}

fn parse_padding(input: ParseStream) -> syn::Result<Padding> {
    let policy: Ident = input.parse()?;
    let expected = "expected `none`, `block(size)`, or `length(len)`";

    if policy == "none" {
        return Ok(Padding::None(policy.span()));
    }
    if policy != "block" && policy != "length" {
        return Err(syn::Error::new(policy.span(), expected));
    }

    let content;
    parenthesized!(content in input);
    let parameter: LitInt = content.parse()?;
    let value = parameter.base10_parse::<usize>()?;

    // Mirror the const assertions in `cryptbox::Padding`.
    if policy == "block" {
        if value < 2 {
            return Err(syn::Error::new(
                parameter.span(),
                "padding block size must be at least 2",
            ));
        }
        Ok(Padding::Block(parameter))
    } else {
        if value < 1 {
            return Err(syn::Error::new(
                parameter.span(),
                "fixed padding length must be at least 1",
            ));
        }
        Ok(Padding::Length(parameter))
    }
}

fn parse_bits(input: ParseStream) -> syn::Result<LitInt> {
    let bits: LitInt = input.parse()?;
    let value = bits.base10_parse::<u16>()?;

    // Mirror the const assertion in `cryptbox::BlindIndexSpec`.
    if !(1..=256).contains(&value) {
        return Err(syn::Error::new(
            bits.span(),
            "blind-index bits must be between 1 and 256",
        ));
    }

    Ok(bits)
}
