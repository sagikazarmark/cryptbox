//! Expands `#[derive(Record)]`.

use proc_macro2::{Group, Span, TokenStream, TokenTree};
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::{
    Data, DeriveInput, Fields, GenericArgument, Ident, LitInt, LitStr, Meta, Path, PathArguments,
    Token, Type, Visibility, ext::IdentExt, meta::ParseNestedMeta, punctuated::Punctuated,
    spanned::Spanned,
};

use crate::attr::{
    Errors, Padding, UuidLiteral, parse_bits, parse_normalizer, parse_padding, parse_uuid,
};

/// The keys of a record field's `#[cryptbox(…)]`.
const FIELD_KEYS: &str = "`record_id`, `seal`, `plaintext`, `codec`, `padding`, `name`, \
                          `blind_index`, or `stored`";

/// What a field is to the record.
enum Role {
    RecordId,
    Seal(Box<Sealing>),
    Plaintext,
}

/// A sealed field's own seal and the blind indexes it writes.
struct Sealing {
    id: UuidLiteral,
    codec: Option<Type>,
    padding: Option<Padding>,
    name: Option<Ident>,
    indexes: Vec<IndexDecl>,
}

/// A blind index a sealed field writes.
struct IndexDecl {
    span: Span,
    id: UuidLiteral,
    bits: LitInt,
    normalize: Path,
    normalizer: LitStr,
    query: Type,
    column: Ident,
}

struct Field<'a> {
    ident: &'a Ident,
    vis: &'a Visibility,
    ty: &'a Type,
    docs: Vec<&'a syn::Attribute>,
    role: Role,
    stored: Vec<Meta>,
}

impl Field<'_> {
    /// For an `Option<T>` field, `T`.
    fn optional_inner(&self) -> Option<&Type> {
        let Type::Path(path) = self.ty else {
            return None;
        };
        let last = path.path.segments.last()?;
        if last.ident != "Option" || path.qself.is_some() {
            return None;
        }
        let PathArguments::AngleBracketed(args) = &last.arguments else {
            return None;
        };
        match args.args.first()? {
            GenericArgument::Type(inner) if args.args.len() == 1 => Some(inner),
            _ => None,
        }
    }

    /// The type a sealed field's seal seals: its type, or `T` of `Option<T>`.
    fn value_type(&self) -> &Type {
        self.optional_inner().unwrap_or(self.ty)
    }

    fn sealing(&self) -> Option<&Sealing> {
        match &self.role {
            Role::Seal(sealing) => Some(sealing),
            _ => None,
        }
    }
}

/// `snake_case` to `PascalCase`.
fn pascal(ident: &Ident) -> String {
    ident
        .unraw()
        .to_string()
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        })
        .collect()
}

fn path_string(path: &Path) -> String {
    path.to_token_stream().to_string().replace(' ', "")
}

/// Parses `stored(…)`: attributes for the stored form, without their `#[…]`.
fn parse_stored(meta: &ParseNestedMeta<'_>) -> syn::Result<Vec<Meta>> {
    let content;
    syn::parenthesized!(content in meta.input);
    Ok(Punctuated::<Meta, Token![,]>::parse_terminated(&content)?
        .into_iter()
        .collect())
}

/// The roles and settings one field's `#[cryptbox(…)]` attributes give it.
#[derive(Default)]
struct FieldAttrs {
    roles: Vec<(Span, &'static str)>,
    seal: Option<UuidLiteral>,
    codec: Option<(Span, Type)>,
    padding: Option<(Span, Padding)>,
    name: Option<(Span, Ident)>,
    indexes: Vec<IndexDecl>,
    stored: Vec<Meta>,
    malformed: bool,
}

fn parse_field_attrs(field: &syn::Field, ident: &Ident, errors: &mut Errors) -> FieldAttrs {
    let mut parsed = FieldAttrs::default();

    for attr in field.attrs.iter().filter(|a| a.path().is_ident("cryptbox")) {
        let result = attr.parse_nested_meta(|meta| {
            let span = meta.path.span();
            if meta.path.is_ident("record_id") {
                parsed.roles.push((span, "record_id"));
            } else if meta.path.is_ident("plaintext") {
                parsed.roles.push((span, "plaintext"));
            } else if meta.path.is_ident("seal") {
                parsed.roles.push((span, "seal"));
                parsed.seal = Some(parse_uuid("seal", meta.value()?)?);
            } else if meta.path.is_ident("codec") {
                parsed.codec = Some((span, meta.value()?.parse()?));
            } else if meta.path.is_ident("padding") {
                parsed.padding = Some((span, parse_padding(meta.value()?)?));
            } else if meta.path.is_ident("name") {
                parsed.name = Some((span, meta.value()?.parse()?));
            } else if meta.path.is_ident("blind_index") {
                parsed.indexes.push(parse_index(ident, &meta)?);
            } else if meta.path.is_ident("stored") {
                parsed.stored.extend(parse_stored(&meta)?);
            } else {
                return Err(meta.error(format!(
                    "unknown `cryptbox` key `{}` on a record field; expected {FIELD_KEYS}",
                    path_string(&meta.path)
                )));
            }
            Ok(())
        });
        if let Err(error) = result {
            errors.push(error);
            parsed.malformed = true;
        }
    }

    parsed
}

fn parse_field<'a>(field: &'a syn::Field, errors: &mut Errors) -> Option<Field<'a>> {
    let ident = field.ident.as_ref()?;
    let mut attrs = parse_field_attrs(field, ident, errors);

    let role = match attrs.roles.as_slice() {
        // The attribute's own error already says what is wrong.
        [] if attrs.malformed => return None,
        [] => {
            errors.push(syn::Error::new(
                ident.span(),
                format!(
                    "`{ident}` has no role: mark it `#[cryptbox(seal = \"<uuid>\")]` to encrypt \
                     it, `#[cryptbox(plaintext)]` to store it as it is, or \
                     `#[cryptbox(record_id)]`"
                ),
            ));
            return None;
        }
        [(_, role)] => *role,
        [_, (span, _), ..] => {
            errors.push(syn::Error::new(
                *span,
                format!(
                    "`{ident}` has more than one role: a field is exactly one of `record_id`, \
                     `seal`, or `plaintext`"
                ),
            ));
            return None;
        }
    };

    let role = if role == "seal" {
        let id = attrs.seal.take()?;
        Role::Seal(Box::new(Sealing {
            id,
            codec: attrs.codec.take().map(|(_, codec)| codec),
            padding: attrs.padding.take().map(|(_, padding)| padding),
            name: attrs.name.take().map(|(_, name)| name),
            indexes: std::mem::take(&mut attrs.indexes),
        }))
    } else {
        let configured = [
            attrs.codec.as_ref().map(|(span, _)| (*span, "codec")),
            attrs.padding.as_ref().map(|(span, _)| (*span, "padding")),
            attrs.name.as_ref().map(|(span, _)| (*span, "name")),
        ];
        for (span, key) in configured.into_iter().flatten() {
            errors.push(syn::Error::new(
                span,
                format!("`{key}` configures a field's seal; `{ident}` is not sealed"),
            ));
        }
        for index in &attrs.indexes {
            errors.push(syn::Error::new(
                index.span,
                format!("`{ident}` is not sealed, so it has no blind index: seal it to index it"),
            ));
        }
        match role {
            "record_id" => Role::RecordId,
            _ => Role::Plaintext,
        }
    };

    Some(Field {
        ident,
        vis: &field.vis,
        ty: &field.ty,
        docs: field
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("doc"))
            .collect(),
        role,
        stored: attrs.stored,
    })
}

fn parse_index(field: &Ident, meta: &ParseNestedMeta<'_>) -> syn::Result<IndexDecl> {
    let span = meta.path.span();
    let mut id = None;
    let mut bits = None;
    let mut normalize = None;
    let mut normalizer = None;
    let mut query = None;

    meta.parse_nested_meta(|inner| {
        if inner.path.is_ident("id") {
            id = Some(parse_uuid("id", inner.value()?)?);
        } else if inner.path.is_ident("bits") {
            bits = Some(parse_bits(inner.value()?)?);
        } else if inner.path.is_ident("normalize") {
            normalize = Some(inner.value()?.parse()?);
        } else if inner.path.is_ident("normalizer") {
            normalizer = Some(parse_normalizer(inner.value()?)?);
        } else if inner.path.is_ident("query") {
            query = Some(inner.value()?.parse()?);
        } else {
            return Err(inner.error(format!(
                "unknown `blind_index` key `{}`; expected one of `id`, `bits`, `normalize`, \
                 `normalizer`, or `query`",
                path_string(&inner.path)
            )));
        }
        Ok(())
    })?;

    let missing = |key: &str, example: &str| {
        syn::Error::new(
            span,
            format!("`blind_index` needs `{key}`: add `{key} = {example}`"),
        )
    };
    Ok(IndexDecl {
        span,
        id: id.ok_or_else(|| missing("id", "\"<uuid>\""))?,
        bits: bits.ok_or_else(|| missing("bits", "32"))?,
        normalize: normalize.ok_or_else(|| missing("normalize", "normalize_fn"))?,
        normalizer: normalizer.ok_or_else(|| missing("normalizer", "\"email/1\""))?,
        query: query.unwrap_or_else(|| syn::parse_quote!(str)),
        column: format_ident!("{}_index", field.unraw()),
    })
}

/// The record's own `#[cryptbox(…)]`: the stored form's name and attributes.
struct RecordAttrs {
    krate: Path,
    stored_name: Option<Ident>,
    stored: Vec<Meta>,
}

fn parse_record_attrs(input: &DeriveInput, errors: &mut Errors) -> RecordAttrs {
    let mut parsed = RecordAttrs {
        krate: crate::attr::krate(),
        stored_name: None,
        stored: Vec::new(),
    };
    let type_name = |value: &syn::Expr| {
        let syn::Expr::Path(path) = value else {
            return None;
        };
        path.path.get_ident().cloned()
    };

    for attr in input.attrs.iter().filter(|a| a.path().is_ident("cryptbox")) {
        let result = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("stored") {
                for item in parse_stored(&meta)? {
                    match &item {
                        Meta::NameValue(pair) if pair.path.is_ident("name") => {
                            parsed.stored_name = Some(type_name(&pair.value).ok_or_else(|| {
                                syn::Error::new_spanned(
                                    &pair.value,
                                    "`name` takes a type name, such as `name = CustomerRow`",
                                )
                            })?);
                        }
                        _ => parsed.stored.push(item),
                    }
                }
            } else {
                return Err(meta.error(format!(
                    "unknown `cryptbox` key `{}` on a record; expected `stored(…)`",
                    path_string(&meta.path)
                )));
            }
            Ok(())
        });
        if let Err(error) = result {
            errors.push(error);
        }
    }

    parsed
}

/// Reports each ID after the first that repeats an earlier one, naming the
/// field that declared it first.
fn check_distinct<'a>(
    ids: impl Iterator<Item = (&'a UuidLiteral, &'a Ident)>,
    message: impl Fn(&Ident) -> String,
    errors: &mut Errors,
) {
    let mut seen: Vec<(u128, &Ident)> = Vec::new();
    for (id, field) in ids {
        match seen.iter().find(|(value, _)| *value == id.value()) {
            Some((_, first)) => errors.push(syn::Error::new(id.span(), message(first))),
            None => seen.push((id.value(), field)),
        }
    }
}

/// Checks the record as a whole: one record ID, at least one sealed field,
/// distinct seal and index IDs, and distinct columns.
fn check_record(name: &Ident, fields: &[Field<'_>], errors: &mut Errors) {
    let record_ids: Vec<_> = fields
        .iter()
        .filter(|f| matches!(f.role, Role::RecordId))
        .collect();
    match record_ids.as_slice() {
        [] => errors.push(syn::Error::new(
            name.span(),
            format!(
                "`{name}` needs a record ID: mark the field that holds it \
                 `#[cryptbox(record_id)]`"
            ),
        )),
        [_] => {}
        [_, extra, ..] => errors.push(syn::Error::new(
            extra.ident.span(),
            "a record has one record ID: mark only one field `#[cryptbox(record_id)]`",
        )),
    }
    if !fields.iter().any(|f| matches!(f.role, Role::Seal(_))) {
        errors.push(syn::Error::new(
            name.span(),
            format!(
                "`{name}` has no sealed field: mark one `#[cryptbox(seal = \"<uuid>\")]`, or \
                 store it without `#[derive(Record)]`"
            ),
        ));
    }

    for field in fields.iter().filter(|f| matches!(f.role, Role::RecordId)) {
        if field.optional_inner().is_some() {
            errors.push(syn::Error::new(
                field.ty.span(),
                format!(
                    "`{}` is bound into every sealed field, so it can't be optional",
                    field.ident
                ),
            ));
        }
    }

    // Fields that share a seal ID share a context, so their stored values
    // could be swapped undetected.
    check_distinct(
        fields
            .iter()
            .filter_map(|f| Some((&f.sealing()?.id, f.ident))),
        |first| {
            format!(
                "`{first}` already declares this seal ID: give each sealed field its own, or \
                 their values can be swapped undetected"
            )
        },
        errors,
    );
    check_distinct(
        fields.iter().flat_map(|f| {
            f.sealing()
                .map_or(&[][..], |s| &s.indexes)
                .iter()
                .map(|index| (&index.id, f.ident))
        }),
        |first| format!("`{first}` already declares this index ID: give each blind index its own"),
        errors,
    );

    let mut columns: Vec<&Ident> = fields.iter().map(|f| f.ident).collect();
    for field in fields {
        for index in field.sealing().map_or(&[][..], |s| &s.indexes) {
            if columns.contains(&&index.column) {
                errors.push(syn::Error::new(
                    index.column.span(),
                    format!(
                        "the blind index of `{}` is stored in the `{}` column, which is already a \
                         field: rename that field",
                        field.ident, index.column
                    ),
                ));
            }
            columns.push(&index.column);
        }
    }
}

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let mut errors = Errors::default();

    if !input.generics.params.is_empty() {
        errors.push(syn::Error::new_spanned(
            &input.generics,
            "`Record` can't be derived for a generic type: its seals are persistent schema",
        ));
    }
    let attrs = parse_record_attrs(input, &mut errors);
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            name.span(),
            "`Record` is derived for a struct",
        ));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new(
            name.span(),
            "`Record` needs named fields: they become the stored form's fields",
        ));
    };
    let fields: Vec<Field<'_>> = named
        .named
        .iter()
        .filter_map(|field| parse_field(field, &mut errors))
        .collect();
    errors = errors.check()?;
    check_record(name, &fields, &mut errors);
    errors.finish()?;

    Ok(Expansion::new(input, attrs, &fields).tokens())
}

/// `tokens` with every token spanned at `span`, so that the compiler reports an
/// error in them there.
fn respan(tokens: TokenStream, span: Span) -> TokenStream {
    tokens
        .into_iter()
        .map(|tree| match tree {
            TokenTree::Group(group) => {
                let mut respanned = Group::new(group.delimiter(), respan(group.stream(), span));
                respanned.set_span(span);
                TokenTree::Group(respanned)
            }
            mut tree => {
                tree.set_span(span);
                tree
            }
        })
        .collect()
}

/// Runs `body` on the value `value` of `field` in `from`, which may be absent.
fn each_value(
    field: &Field<'_>,
    from: &TokenStream,
    value: &Ident,
    body: &TokenStream,
) -> TokenStream {
    let ident = field.ident;
    if field.optional_inner().is_none() {
        return quote!({ let #value = &#from.#ident; #body });
    }

    quote! {
        match &#from.#ident {
            ::core::option::Option::Some(#value) => ::core::option::Option::Some(#body),
            ::core::option::Option::None => ::core::option::Option::None,
        }
    }
}

/// A sealed field's seal: its visibility, value, codec, and padding.
struct SealItem<'t> {
    vis: &'t Visibility,
    value: &'t Type,
    codec: &'t TokenStream,
    padding: &'t TokenStream,
}

impl SealItem<'_> {
    fn tokens(&self, krate: &Path, name: &Ident, doc: &str, id: &UuidLiteral) -> TokenStream {
        let Self {
            vis,
            value,
            codec,
            padding,
        } = self;

        quote! {
            #[doc = #doc]
            #vis struct #name;

            const _: () = {
                #[automatically_derived]
                impl #krate::Seal for #name {
                    const ID: #krate::SealId = #krate::SealId::from_u128(#id);
                    const PADDING: #krate::Padding = #padding;
                    type Value = #value;
                    type Codec = #codec;
                }
            };
        }
    }
}

/// Everything the expansion names, computed once.
struct Expansion<'a> {
    input: &'a DeriveInput,
    krate: Path,
    stored_name: Ident,
    stored_attrs: Vec<Meta>,
    fields: &'a [Field<'a>],
    record_id: &'a Field<'a>,
}

impl<'a> Expansion<'a> {
    fn new(input: &'a DeriveInput, attrs: RecordAttrs, fields: &'a [Field<'a>]) -> Self {
        let name = &input.ident;
        Self {
            input,
            krate: attrs.krate,
            stored_name: attrs
                .stored_name
                .unwrap_or_else(|| format_ident!("Stored{}", name.unraw(), span = name.span())),
            stored_attrs: attrs.stored,
            fields,
            record_id: fields
                .iter()
                .find(|f| matches!(f.role, Role::RecordId))
                .expect("the record ID is checked above"),
        }
    }

    fn seal_name(&self, field: &Field<'_>, sealing: &Sealing) -> Ident {
        sealing.name.clone().unwrap_or_else(|| {
            format_ident!(
                "{}{}",
                self.input.ident.unraw(),
                pascal(field.ident),
                span = field.ident.span()
            )
        })
    }

    fn spec_name(&self, index: &IndexDecl) -> Ident {
        format_ident!(
            "{}{}",
            self.input.ident.unraw(),
            pascal(&index.column),
            span = index.column.span()
        )
    }

    /// The context of the record's sealed fields: its record ID. Spanned at the
    /// record ID's type, where a type that is not a record ID type is reported.
    fn context(&self) -> TokenStream {
        let krate = &self.krate;
        let ty = self.record_id.ty;
        respan(quote!(#krate::InRecord<#ty>), ty.span())
    }

    fn tokens(&self) -> TokenStream {
        let krate = &self.krate;
        // First, and spanned at the field: a record ID of another type is
        // reported there.
        let ty = self.record_id.ty;
        let check = quote_spanned! {ty.span()=>
            const _: fn() = || {
                fn check<T: #krate::RecordIdType>() {}
                check::<#ty>();
            };
        };
        let seals = self.fields.iter().filter_map(|f| self.seal_items(f));
        let stored = self.stored_struct();
        let record = self.record_impl();
        let handles = self.handles();

        quote! {
            #check
            #(#seals)*
            #stored
            #record
            #handles
        }
    }

    /// A sealed field's seal and the specs of its blind indexes.
    fn seal_items(&self, field: &Field<'_>) -> Option<TokenStream> {
        let sealing = field.sealing()?;
        let krate = &self.krate;
        let record = &self.input.ident;
        let seal = self.seal_name(field, sealing);
        let value = field.value_type();
        // Never inferred from a shape: without a codec, the value type's
        // built-in default applies, and a type without one reports it.
        let codec = sealing.codec.as_ref().map_or_else(
            || quote_spanned!(value.span()=> <#value as #krate::__private::DefaultCodec>::Codec),
            |codec| quote!(#codec),
        );
        let padding = sealing.padding.as_ref().map_or_else(
            || quote!(#krate::Padding::NONE),
            |padding| padding.to_tokens(krate),
        );
        let specs: Vec<Ident> = sealing
            .indexes
            .iter()
            .map(|index| self.spec_name(index))
            .collect();
        let item = SealItem {
            vis: field.vis,
            value,
            codec: &codec,
            padding: &padding,
        };

        let current = item.tokens(
            krate,
            &seal,
            &format!(
                "The seal of `{record}::{}`, which `#[derive(Record)]` declares.",
                field.ident
            ),
            &sealing.id,
        );
        let indexes = sealing
            .indexes
            .iter()
            .zip(&specs)
            .map(|(index, spec)| self.index_spec(field, &seal, index, spec));
        Some(quote! {
            #current
            #(#indexes)*
        })
    }

    /// The spec of a blind index `field` writes.
    fn index_spec(
        &self,
        field: &Field<'_>,
        seal: &Ident,
        index: &IndexDecl,
        spec: &Ident,
    ) -> TokenStream {
        let krate = &self.krate;
        let record = &self.input.ident;
        let vis = field.vis;
        let value = field.value_type();
        let IndexDecl {
            id,
            bits,
            normalize,
            normalizer,
            query,
            column,
            ..
        } = index;
        let query_arg = Ident::new("query", Span::mixed_site());
        let value_arg = Ident::new("value", Span::mixed_site());
        let normalize_value = quote_spanned!(normalize.span()=> #normalize(#value_arg));
        let normalized = quote! {
            ::core::result::Result<
                #krate::__private::Zeroizing<::std::vec::Vec<u8>>,
                #krate::BlindIndexError,
            >
        };
        let doc = format!("The `{column}` blind index of `{record}::{}`.", field.ident);

        quote! {
            #[doc = #doc]
            #vis struct #spec;

            const _: () = {
                #[automatically_derived]
                impl #krate::BlindIndexSpec for #spec {
                    type Seal = #seal;
                    const ID: #krate::IndexId = #krate::IndexId::from_u128(#id);
                    const BITS: u16 = #bits;
                    const NORMALIZER: &'static str = #normalizer;
                    type Query = #query;

                    fn normalize_query(#query_arg: &#query) -> #normalized {
                        #normalize(#query_arg)
                    }

                    fn normalize_value(#value_arg: &#value) -> #normalized {
                        #normalize_value
                    }
                }
            };
        }
    }

    /// The stored form: every field as it is, sealed fields as
    /// `Sealed<F, InRecord<Id>>`, and
    /// each blind index in a column after its field.
    fn stored_struct(&self) -> TokenStream {
        let krate = &self.krate;
        let name = &self.input.ident;
        let vis = &self.input.vis;
        let stored_name = &self.stored_name;
        let stored_attrs = &self.stored_attrs;
        let doc = format!("The stored form of [`{name}`].");

        let fields = self.fields.iter().map(|field| {
            let ident = field.ident;
            let vis = field.vis;
            let docs = &field.docs;
            let forwarded = field.stored.iter().map(|meta| quote!(#[#meta]));
            let Some(sealing) = field.sealing() else {
                let ty = field.ty;
                return quote!(#(#docs)* #(#forwarded)* #vis #ident: #ty,);
            };

            let optional = field.optional_inner().is_some();
            let wrap = |ty: TokenStream| {
                if optional {
                    quote!(::core::option::Option<#ty>)
                } else {
                    ty
                }
            };
            let seal = self.seal_name(field, sealing);
            let context = self.context();
            let sealed = wrap(quote!(#krate::Sealed<#seal, #context>));
            let indexes = sealing.indexes.iter().map(|index| {
                let spec = self.spec_name(index);
                let column = &index.column;
                let ty = wrap(quote!(#krate::BlindIndex<#spec>));
                let doc = format!("The `{column}` blind index of `{ident}`.");
                quote!(#[doc = #doc] #vis #column: #ty,)
            });
            quote! {
                #(#docs)* #(#forwarded)* #vis #ident: #sealed,
                #(#indexes)*
            }
        });

        quote! {
            #[doc = #doc]
            #(#[#stored_attrs])*
            #vis struct #stored_name {
                #(#fields)*
            }
        }
    }

    fn record_impl(&self) -> TokenStream {
        let krate = &self.krate;
        let name = &self.input.ident;
        let stored_name = &self.stored_name;
        let keys = Ident::new("keys", Span::mixed_site());
        let stored = Ident::new("stored", Span::mixed_site());
        let value = Ident::new("value", Span::mixed_site());
        let context = self.context();
        let record_id = self.record_id.ident;
        // Spanned at the record ID's type: a type that is not a record ID type is
        // reported there.
        let id_span = self.record_id.ty.span();
        let seal_in =
            |seal: &Ident| respan(quote!(#krate::Sealed::<#seal, #context>::seal_in), id_span);
        let open_in = respan(quote!(#krate::Sealed::open_in), id_span);
        let context_type = quote_spanned!(id_span=> type Context = #context;);

        let mut seals = Vec::new();
        let mut opens = Vec::new();
        let mut stored_fields = Vec::new();
        let mut opened_fields = Vec::new();
        for field in self.fields {
            let ident = field.ident;
            let Some(sealing) = field.sealing() else {
                let ty = field.ty;
                stored_fields.push(
                    quote_spanned!(ty.span()=> #ident: ::core::clone::Clone::clone(&self.#ident)),
                );
                opened_fields.push(quote!(#ident: #stored.#ident));
                continue;
            };

            let seal = self.seal_name(field, sealing);
            let each =
                |from: TokenStream, body: TokenStream| each_value(field, &from, &value, &body);
            let sealed = each(quote!(self), {
                let seal_in = seal_in(&seal);
                quote!(#seal_in(#value, &self.#record_id, #keys)?)
            });
            let opened = each(
                quote!(#stored),
                quote!(#open_in(#value, &#stored.#record_id, #keys)?),
            );
            seals.push(quote!(let #ident = #sealed;));
            opens.push(quote!(let #ident = #opened;));
            stored_fields.push(quote!(#ident));
            opened_fields.push(quote!(#ident));

            for index in &sealing.indexes {
                let spec = self.spec_name(index);
                let column = &index.column;
                let derived = each(
                    quote!(self),
                    quote! {
                        #krate::BlindIndex::<#spec>::derive(
                            #value,
                            #krate::RecordKeys::record_blind_index_keyring(#keys)?,
                        )?
                    },
                );
                seals.push(quote!(let #column = #derived;));
                stored_fields.push(quote!(#column));
            }
        }

        let schema = self.schema_consts();

        quote! {
            const _: () = {
                #[automatically_derived]
                impl #krate::__private::DerivedRecord for #name {}

                #[automatically_derived]
                impl #krate::Record for #name {
                    type Stored = #stored_name;
                    #context_type

                    #schema

                    // Bare fields are cloned with the field's span, so a
                    // non-Clone type errors at the field; that span makes
                    // clippy lint a Copy record ID in the user's crate.
                    #[allow(clippy::clone_on_copy)]
                    fn seal<K>(
                        &self,
                        #keys: &K,
                    ) -> ::core::result::Result<#stored_name, #krate::Error>
                    where
                        K: #krate::RecordKeys + ?::core::marker::Sized,
                    {
                        #(#seals)*

                        ::core::result::Result::Ok(#stored_name {
                            #(#stored_fields,)*
                        })
                    }

                    fn open<K>(
                        #stored: #stored_name,
                        #keys: &K,
                    ) -> ::core::result::Result<Self, #krate::Error>
                    where
                        K: #krate::EncryptionKeys + ?::core::marker::Sized,
                    {
                        #(#opens)*

                        ::core::result::Result::Ok(Self {
                            #(#opened_fields,)*
                        })
                    }
                }
            };
        }
    }

    /// The record's schema for the manifest: its seals' IDs, and the names of its
    /// record ID and plaintext fields, in field order.
    fn schema_consts(&self) -> TokenStream {
        let krate = &self.krate;
        let seal_ids = self
            .fields
            .iter()
            .filter_map(|f| Some(self.seal_name(f, f.sealing()?)))
            .map(|seal| quote!(<#seal as #krate::Seal>::ID));
        let record_id = LitStr::new(
            &self.record_id.ident.unraw().to_string(),
            self.record_id.ident.span(),
        );
        let names = |role: fn(&Role) -> bool| -> Vec<LitStr> {
            self.fields
                .iter()
                .filter(|f| role(&f.role))
                .map(|f| LitStr::new(&f.ident.unraw().to_string(), f.ident.span()))
                .collect()
        };
        let plaintext = names(|role| matches!(role, Role::Plaintext));
        quote! {
            const SEALS: &'static [#krate::SealId] = &[#(#seal_ids),*];
            const RECORD_ID: &'static str = #record_id;
            const PLAINTEXT: &'static [&'static str] = &[#(#plaintext),*];
        }
    }

    /// Each blind index's handle, a const named after its column.
    fn handles(&self) -> TokenStream {
        let krate = &self.krate;
        let name = &self.input.ident;
        let mut consts = Vec::new();

        for field in self.fields {
            let Some(sealing) = field.sealing() else {
                continue;
            };
            let ident = field.ident;
            let vis = field.vis;
            let value_ty = field.value_type();
            let value = if field.optional_inner().is_some() {
                quote!(record.#ident.as_ref())
            } else {
                quote!(::core::option::Option::Some(&record.#ident))
            };

            for index in &sealing.indexes {
                let spec = self.spec_name(index);
                let column = &index.column;
                let handle = format_ident!(
                    "{}",
                    column.unraw().to_string().to_uppercase(),
                    span = column.span()
                );
                let doc = format!("The `{column}` blind index of `{ident}`.");
                consts.push(quote! {
                    #[doc = #doc]
                    #vis const #handle: #krate::Index<#name, #spec> = #krate::Index::__new(
                        |record: &#name| -> ::core::option::Option<&#value_ty> { #value },
                    );
                });
            }
        }

        if consts.is_empty() {
            return TokenStream::new();
        }
        quote! {
            #[automatically_derived]
            impl #name {
                #(#consts)*
            }
        }
    }
}
