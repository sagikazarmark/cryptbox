//! Expands `#[derive(Record)]`.

use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::{
    Attribute, Data, DeriveInput, Fields, Ident, LitStr, Meta, Path, Type, spanned::Spanned,
};

use crate::attr::{
    Attrs, Errors, IndexColumn, Key, Padding, UuidLiteral, parse_index_columns, required,
};
use crate::seal::seal_items;

/// The keys of the struct's `#[record(…)]`.
const KEYS: &[Key] = &[Key::Sealed, Key::Attr, Key::Crate];

/// The keys of a field's own `#[seal(…)]`.
const OWN_SEAL_KEYS: &[Key] = &[
    Key::Id,
    Key::Scope,
    Key::Keys,
    Key::Codec,
    Key::Padding,
    Key::Name,
];

/// One struct field of the record, and how it is stored.
struct Member<'a> {
    decl: &'a syn::Field,
    ident: &'a Ident,
    /// Whether it holds the record ID, `#[record_id]`.
    record_id: bool,
    /// How it is sealed, or `None` when it is stored as it is.
    sealing: Option<Sealing>,
}

/// A member sealed as a cryptbox seal, with the blind indexes it writes.
struct Sealing {
    seal: Type,
    /// The seal the field declares for itself, or `None` for an existing seal.
    own: Option<OwnSeal>,
    indexes: Vec<IndexColumn>,
}

/// A seal a field declares for itself, which the derive generates.
struct OwnSeal {
    name: Ident,
    id: UuidLiteral,
    scope: Option<Type>,
    keys: Option<Type>,
    codec: Option<Type>,
    padding: Option<Padding>,
}

impl OwnSeal {
    /// The declared scope, without the record.
    fn scope(&self) -> TokenStream {
        self.scope
            .as_ref()
            .map_or_else(|| quote!(()), |scope| quote!(#scope))
    }

    /// The keys view, which defaults to the declared scope.
    fn keys(&self) -> TokenStream {
        self.keys
            .as_ref()
            .map_or_else(|| self.scope(), |keys| quote!(#keys))
    }
}

impl Member<'_> {
    /// The `#[doc]` and `#[sqlx]` attributes the sealed struct keeps.
    fn forwarded_attrs(&self) -> impl Iterator<Item = &Attribute> {
        self.decl
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("doc") || attr.path().is_ident("sqlx"))
    }

    /// The blind indexes it writes, if any.
    fn indexes(&self) -> &[IndexColumn] {
        self.sealing
            .as_ref()
            .map_or(&[], |sealing| sealing.indexes.as_slice())
    }
}

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut errors = Errors::default();
    let mut attrs = Attrs::parse(&input.attrs, "record", KEYS, &mut errors);
    let krate = attrs.krate();
    let name = &input.ident;

    let sealed_name = required(
        attrs.sealed.take(),
        &attrs,
        Key::Sealed,
        name,
        "SealedName",
        &mut errors,
    );
    let fields = struct_fields(input, &mut errors);
    let members = parse_members(name, &fields, &mut errors);
    errors = errors.check()?;
    let Some(sealed_name) = sealed_name else {
        unreachable!("missing keys are reported above");
    };
    check_members(name, &members, &mut errors);
    errors.finish()?;
    let record = members
        .iter()
        .find(|member| member.record_id)
        .expect("the record ID field is checked above");
    let (record, record_ty) = (record.ident, &record.decl.ty);

    let Some(first) = members.iter().find_map(|member| member.sealing.as_ref()) else {
        unreachable!("a record without sealed fields is reported above");
    };
    // A field's own seal may be private, so the record names its declared scope
    // and keys view rather than a projection through it.
    let (record_scope, record_keys) = if let Some(own) = &first.own {
        (own.scope(), own.keys())
    } else {
        let seal = &first.seal;
        (
            quote!(<<#seal as #krate::Seal>::Scope as #krate::SealScope>::Parts),
            quote!(<#seal as #krate::Seal>::Keys),
        )
    };
    let own_seals = members
        .iter()
        .filter_map(|member| own_seal(&krate, name, record_ty, member));
    let sealed_struct = sealed_struct(input, &attrs, &krate, &sealed_name, &members);
    let checks = members
        .iter()
        .filter_map(|member| index_check(&krate, member));
    let sealers = members
        .iter()
        .filter_map(|member| field_sealer(&krate, record_ty, member));
    let indexed_by = members
        .iter()
        .flat_map(|member| indexed_by(&krate, name, member));
    let seal = seal_fn(&krate, &sealed_name, record, &members);
    let open = open_fn(&krate, &sealed_name, record, &members);

    Ok(quote! {
        #(#own_seals)*

        #sealed_struct

        const _: () = {
            #(#checks)*

            #[automatically_derived]
            impl #name {
                #(#sealers)*
            }

            #[automatically_derived]
            impl #krate::Record for #name {
                type Sealed = #sealed_name;
                type Scope = #record_scope;
                type Keys = #record_keys;

                #seal

                #open
            }

            #(#indexed_by)*
        };
    })
}

/// The named fields of a non-generic struct.
fn struct_fields<'a>(input: &'a DeriveInput, errors: &mut Errors) -> Vec<&'a syn::Field> {
    if !input.generics.params.is_empty() {
        errors.push(syn::Error::new_spanned(
            &input.generics,
            "`Record` can't be derived for a generic type",
        ));
    }

    let Data::Struct(data) = &input.data else {
        errors.push(syn::Error::new(
            input.ident.span(),
            "`Record` can only be derived for a struct",
        ));
        return Vec::new();
    };

    match &data.fields {
        Fields::Named(fields) => fields.named.iter().collect(),
        Fields::Unit => Vec::new(),
        Fields::Unnamed(fields) => {
            errors.push(syn::Error::new_spanned(
                fields,
                "`Record` needs named fields: the sealed struct keeps their names",
            ));
            Vec::new()
        }
    }
}

/// Parses how each struct field is stored: sealed with `#[seal…]`, or as it is.
fn parse_members<'a>(
    name: &Ident,
    fields: &[&'a syn::Field],
    errors: &mut Errors,
) -> Vec<Member<'a>> {
    let mut members = Vec::new();

    for decl in fields {
        let Some(ident) = &decl.ident else { continue };
        let record_id = parse_record_id(decl, errors);
        let mut indexes = Vec::new();
        for attr in decl
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("blind_index"))
        {
            match parse_index_columns(attr) {
                Ok(columns) => indexes.extend(columns),
                Err(error) => errors.push(error),
            }
        }

        let mut seals = decl
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("seal"));
        let sealing = match (seals.next(), seals.next()) {
            (None, _) => {
                if !indexes.is_empty() {
                    errors.push(syn::Error::new(
                        ident.span(),
                        format!("`{ident}` is stored as it is, so it has no blind indexes: seal it to index it"),
                    ));
                }
                None
            }
            (Some(_), Some(extra)) => {
                errors.push(syn::Error::new_spanned(
                    extra,
                    "duplicate `seal`: a field has one seal",
                ));
                continue;
            }
            (Some(attr), None) => {
                let Some(seal) = parse_seal(name, ident, decl, attr, errors) else {
                    continue;
                };
                Some(Sealing { indexes, ..seal })
            }
        };

        members.push(Member {
            decl,
            ident,
            record_id,
            sealing,
        });
    }

    members
}

/// Whether the field is marked `#[record_id]`.
fn parse_record_id(decl: &syn::Field, errors: &mut Errors) -> bool {
    let mut marked = false;
    for attr in decl
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("record_id"))
    {
        if !matches!(attr.meta, Meta::Path(_)) {
            errors.push(syn::Error::new_spanned(
                attr,
                "`#[record_id]` takes no arguments",
            ));
        } else if marked {
            errors.push(syn::Error::new_spanned(attr, "duplicate `record_id`"));
        }
        marked = true;
    }

    marked
}

/// Parses a field's `#[seal…]`: bare, the field's type as its seal; `#[seal(F)]`,
/// an existing seal; or `#[seal(id = "…", …)]`, the field's own seal.
fn parse_seal(
    record: &Ident,
    ident: &Ident,
    decl: &syn::Field,
    attr: &Attribute,
    errors: &mut Errors,
) -> Option<Sealing> {
    let existing = |seal| {
        Some(Sealing {
            seal,
            own: None,
            indexes: Vec::new(),
        })
    };
    // Nothing is inferred from names: a type that is not a seal fails to compile
    // where it is named.
    match &attr.meta {
        Meta::Path(_) => return existing(decl.ty.clone()),
        Meta::NameValue(meta) => {
            errors.push(syn::Error::new_spanned(
                meta,
                "write `#[seal(F)]` to use an existing seal, or `#[seal(id = \"<uuid>\")]` to \
                 declare the field's own",
            ));
            return None;
        }
        Meta::List(_) => {}
    }
    if let Ok(seal) = attr.parse_args::<Type>()
        && !is_key(&seal)
    {
        return existing(seal);
    }

    let mut attrs = Attrs::parse(std::slice::from_ref(attr), "seal", OWN_SEAL_KEYS, errors);
    let Some(id) = attrs.id.take() else {
        // An invalid `id` is already reported.
        if !attrs.seen(Key::Id) {
            errors.push(syn::Error::new_spanned(
                attr,
                format!(
                    "`{ident}` declares its own seal: add its ID with \
                     `#[seal(id = \"<uuid>\", …)]`, or use an existing seal with `#[seal(F)]`"
                ),
            ));
        }
        return None;
    };
    let seal_name = attrs
        .name
        .take()
        .unwrap_or_else(|| own_seal_name(record, ident));

    Some(Sealing {
        seal: syn::parse_quote!(#seal_name),
        own: Some(OwnSeal {
            name: seal_name,
            id,
            scope: attrs.scope.take(),
            keys: attrs.keys.take(),
            codec: attrs.codec.take(),
            padding: attrs.padding.take(),
        }),
        indexes: Vec::new(),
    })
}

/// Whether `ty` is a lone key of the field's own `#[seal(…)]`, such as `id`
/// without its value, rather than an existing seal.
fn is_key(ty: &Type) -> bool {
    let Type::Path(path) = ty else { return false };
    path.qself.is_none()
        && path
            .path
            .get_ident()
            .is_some_and(|ident| OWN_SEAL_KEYS.iter().any(|key| ident == key.name()))
}

/// The default name of a field's own seal: the record's name and the field's,
/// as `CustomerEmail` for `Customer::email`.
fn own_seal_name(record: &Ident, field: &Ident) -> Ident {
    let field = field.to_string();
    let pascal: String = field
        .trim_start_matches("r#")
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        })
        .collect();

    // The name resolves where the record is declared.
    Ident::new(&format!("{record}{pascal}"), record.span())
}
/// Checks the record ID field and the names the sealed struct adds.
fn check_members(name: &Ident, members: &[Member<'_>], errors: &mut Errors) {
    let mut records = members.iter().filter(|member| member.record_id);
    match (records.next(), records.next()) {
        (None, _) => errors.push(syn::Error::new(
            name.span(),
            format!("`{name}` needs a record ID: mark the field that holds it `#[record_id]`"),
        )),
        (Some(_), Some(other)) => errors.push(syn::Error::new(
            other.ident.span(),
            "a record has one record ID: mark only one field `#[record_id]`",
        )),
        (Some(member), None) if member.sealing.is_some() => {
            errors.push(syn::Error::new(
                member.ident.span(),
                format!(
                    "the record ID `{}` is never encrypted: the seals bound to the record \
                     bind it, so it must be readable before the row is opened; \
                     remove its `#[seal]`",
                    member.ident
                ),
            ));
        }
        (Some(_), None) => {}
    }

    // Two fields of one seal could have their values swapped within a row.
    let mut seals: Vec<(String, &Ident)> = Vec::new();
    for member in members {
        let Some(sealing) = &member.sealing else {
            continue;
        };
        let seal = sealing.seal.to_token_stream().to_string();
        match seals.iter().find(|(other, _)| *other == seal) {
            Some((_, other)) => errors.push(syn::Error::new(
                sealing.seal.span(),
                format!(
                    "`{}` also seals `{other}`: give each field its own seal, or the two \
                     fields' values could be swapped within a row",
                    sealing.seal.to_token_stream()
                ),
            )),
            None => seals.push((seal, member.ident)),
        }
    }

    if members.iter().all(|member| member.sealing.is_none()) {
        errors.push(syn::Error::new(
            name.span(),
            "a record needs at least one sealed field: declare a seal on one with `#[seal(id = \"<uuid>\")]`",
        ));
    }

    // The sealed struct holds the fields and the index columns side by side.
    let mut names: Vec<&Ident> = members.iter().map(|member| member.ident).collect();
    for index in members.iter().flat_map(Member::indexes) {
        if names.contains(&&index.column) {
            errors.push(syn::Error::new(
                index.column.span(),
                format!(
                    "the sealed struct already has a field `{}`: name this index's column otherwise",
                    index.column
                ),
            ));
        } else {
            names.push(&index.column);
        }
    }
}

/// The sealed struct: plaintext fields as they are, sealed fields as
/// `Sealed<F>`, and each index after the field it indexes.
fn sealed_struct(
    input: &DeriveInput,
    attrs: &Attrs,
    krate: &Path,
    sealed_name: &Ident,
    members: &[Member<'_>],
) -> TokenStream {
    let name = &input.ident;
    let vis = &input.vis;
    let doc = LitStr::new(
        &format!("The sealed form of [`{name}`], as it is stored."),
        sealed_name.span(),
    );
    let extra = attrs.attr.iter().flatten();
    let sqlx = input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("sqlx"));

    let fields = members.iter().map(|member| {
        let forwarded = member.forwarded_attrs();
        let vis = &member.decl.vis;
        let ident = member.ident;
        let Some(Sealing { seal, indexes, .. }) = &member.sealing else {
            let ty = &member.decl.ty;
            return quote!(#(#forwarded)* #vis #ident: #ty,);
        };

        let indexes = indexes.iter().map(|index| {
            let spec = &index.spec;
            let column = &index.column;
            let doc = LitStr::new(
                &format!(
                    "The `{}` blind index of `{ident}`.",
                    quote!(#spec).to_string().replace(' ', "")
                ),
                column.span(),
            );
            quote!(#[doc = #doc] #vis #column: #krate::BlindIndex<#spec>,)
        });
        quote! {
            #(#forwarded)* #vis #ident: #krate::Sealed<#seal>,
            #(#indexes)*
        }
    });

    quote! {
        #[doc = #doc]
        #(#[#extra])*
        #(#sqlx)*
        #vis struct #sealed_name {
            #(#fields)*
        }
    }
}

/// Asserts that a sealed field writes exactly the indexes its seal declares.
fn index_check(krate: &Path, member: &Member<'_>) -> Option<TokenStream> {
    let Sealing { seal, indexes, .. } = member.sealing.as_ref()?;
    let ident = member.ident;
    let specs = indexes.iter().map(|index| &index.spec);
    let message = LitStr::new(
        &format!(
            "`{ident}` must write every blind index its seal declares in `indexes(…)`, \
             each once, and no other: list them as `#[blind_index(Spec as column, …)]`"
        ),
        ident.span(),
    );

    Some(quote_spanned! {seal.span()=>
        const _: () = ::core::assert!(
            #krate::__private::writes_declared_indexes(
                <<#seal as #krate::Seal>::Indexes as #krate::IndexList<#seal>>::IDS,
                &[#(<#specs as #krate::BlindIndexSpec>::ID),*],
            ),
            #message,
        );
    })
}

/// Names the generated code's own parameters and locals, which a field of the
/// same name must not capture.
fn hygienic(name: &str) -> Ident {
    Ident::new(name, Span::mixed_site())
}

/// Like [`hygienic`], but located at `span`, so a type error in the argument
/// points at the field it is passed for.
fn hygienic_at(name: &str, span: Span) -> Ident {
    Ident::new(name, Span::mixed_site().located_at(span))
}

/// `seal_<field>`: seals one field with its indexes, for a partial update.
fn field_sealer(krate: &Path, record_ty: &Type, member: &Member<'_>) -> Option<TokenStream> {
    let Sealing { seal, indexes, .. } = member.sealing.as_ref()?;
    let ident = member.ident;
    let vis = &member.decl.vis;
    let sealer = sealer_name(ident);
    let [value, binding, record, keys, prepared] =
        ["value", "binding", "record", "keys", "prepared"].map(hygienic);
    let args = quote!(#krate::__private::InRecord(#binding, #record));
    let specs: Vec<_> = indexes.iter().map(|index| &index.spec).collect();

    let (doc, bounds, output, body) = if indexes.is_empty() {
        (
            format!(
                "Seals `{ident}` alone under `binding` and the record ID `record`, for a partial update."
            ),
            quote!(#krate::EncryptionKeySource<<#seal as #krate::Seal>::Keys>),
            quote!(#krate::Sealed<#seal>),
            quote!(#krate::Sealed::<#seal>::seal(#value, #args, #keys)),
        )
    } else {
        let locals: Vec<_> = indexes
            .iter()
            .map(|index| hygienic(&index.column.to_string()))
            .collect();
        (
            format!(
                "Seals `{ident}` alone under `binding` and the record ID `record`, with the blind \
                 indexes it stores, for a partial update."
            ),
            quote!(
                #krate::EncryptionKeySource<<#seal as #krate::Seal>::Keys>
                    + #krate::BlindIndexKeySource<<#seal as #krate::Seal>::Keys>
            ),
            quote!((#krate::Sealed<#seal>, #(#krate::BlindIndex<#specs>),*)),
            quote! {
                let #prepared = #krate::Sealed::<#seal>::prepare(#value, #args, #keys)?
                    #(.with_index_with::<#specs>(#keys)?)*;
                #(let #locals = #prepared.index::<#specs>()?.to_blind_index();)*

                ::core::result::Result::Ok((#prepared.into_sealed(), #(#locals),*))
            },
        )
    };

    Some(quote! {
        #[doc = #doc]
        #vis fn #sealer<K>(
            #value: &<#seal as #krate::Seal>::Value,
            #binding: &<<#seal as #krate::Seal>::Scope as #krate::SealScope>::Parts,
            #record: &#record_ty,
            #keys: &K,
        ) -> ::core::result::Result<#output, #krate::Error>
        where
            K: #bounds + ?::core::marker::Sized,
        {
            #body
        }
    })
}

fn sealer_name(ident: &Ident) -> Ident {
    format_ident!("seal_{}", ident.to_string().trim_start_matches("r#"))
}

/// `Record::seal`: every sealed field through its sealer, plaintext fields cloned.
fn seal_fn(
    krate: &Path,
    sealed_name: &Ident,
    record: &Ident,
    members: &[Member<'_>],
) -> TokenStream {
    let [binding, keys] = ["binding", "keys"].map(hygienic);

    let seals = members.iter().filter_map(|member| {
        let Sealing { seal, indexes, .. } = member.sealing.as_ref()?;
        let ident = member.ident;
        let sealer = sealer_name(ident);
        let columns = indexes.iter().map(|index| &index.column);
        let binding = hygienic_at("binding", seal.span());
        // Spanned on the seal, so a seal of another binding is reported there.
        let call = quote_spanned! {seal.span()=>
            Self::#sealer(&self.#ident, #binding, &self.#record, #keys)?
        };

        Some(if indexes.is_empty() {
            quote!(let #ident = #call;)
        } else {
            quote!(let (#ident, #(#columns),*) = #call;)
        })
    });
    let fields = members.iter().map(|member| {
        let ident = member.ident;
        if member.sealing.is_none() {
            return quote!(#ident: ::core::clone::Clone::clone(&self.#ident),);
        }

        let columns = member.indexes().iter().map(|index| &index.column);
        quote!(#ident, #(#columns,)*)
    });

    quote! {
        fn seal<K>(
            &self,
            #binding: &Self::Scope,
            #keys: &K,
        ) -> ::core::result::Result<#sealed_name, #krate::Error>
        where
            K: #krate::EncryptionKeySource<Self::Keys>
                + #krate::BlindIndexKeySource<Self::Keys>
                + ?::core::marker::Sized,
        {
            #(#seals)*

            ::core::result::Result::Ok(#sealed_name {
                #(#fields)*
            })
        }
    }
}

/// `Record::open`: every sealed field opened, plaintext fields moved.
fn open_fn(
    krate: &Path,
    sealed_name: &Ident,
    record: &Ident,
    members: &[Member<'_>],
) -> TokenStream {
    let [sealed, binding, keys, record_id] =
        ["sealed", "binding", "keys", "record_id"].map(hygienic);

    let opens = members.iter().filter_map(|member| {
        let Sealing { seal, .. } = member.sealing.as_ref()?;
        let ident = member.ident;
        let binding = hygienic_at("binding", seal.span());
        // Naming the seal's binding reports a seal of another binding here.
        Some(quote_spanned! {seal.span()=>
            let #ident = #sealed.#ident.open(
                #krate::__private::InRecord::<<<#seal as #krate::Seal>::Scope as #krate::SealScope>::Parts, _>(#binding, #record_id),
                #keys,
            )?;
        })
    });
    let fields = members.iter().map(|member| {
        let ident = member.ident;
        if member.sealing.is_none() {
            quote!(#ident: #sealed.#ident,)
        } else {
            quote!(#ident,)
        }
    });

    quote! {
        fn open<K>(
            #sealed: #sealed_name,
            #binding: &Self::Scope,
            #keys: &K,
        ) -> ::core::result::Result<Self, #krate::Error>
        where
            K: #krate::EncryptionKeySource<Self::Keys> + ?::core::marker::Sized,
        {
            let #record_id = &#sealed.#record;
            #(#opens)*

            ::core::result::Result::Ok(Self {
                #(#fields)*
            })
        }
    }
}

/// `IndexedBy<S>` for each index a field writes.
fn indexed_by<'a>(
    krate: &'a Path,
    name: &'a Ident,
    member: &'a Member<'_>,
) -> impl Iterator<Item = TokenStream> + 'a {
    let ident = member.ident;

    member.indexes().iter().map(move |index| {
        let spec = &index.spec;
        quote! {
            #[automatically_derived]
            impl #krate::IndexedBy<#spec> for #name {
                fn indexed_value(
                    &self,
                ) -> &<<#spec as #krate::BlindIndexSpec>::Seal as #krate::Seal>::Value {
                    &self.#ident
                }
            }
        }
    })
}

/// The seal a field declares for itself: a unit struct with the field's
/// visibility, the least at which the sealed struct can name it, bound to the
/// field's scope and the record's ID.
fn own_seal(
    krate: &Path,
    record: &Ident,
    record_ty: &Type,
    member: &Member<'_>,
) -> Option<TokenStream> {
    let Sealing {
        own: Some(own),
        indexes,
        ..
    } = member.sealing.as_ref()?
    else {
        return None;
    };
    let OwnSeal {
        name,
        id,
        codec,
        padding,
        ..
    } = own;
    let vis = &member.decl.vis;
    let value = &member.decl.ty;
    let doc = format!(
        "The seal of `{record}::{}`, which `#[derive(Record)]` declares.",
        member.ident
    );

    // Never inferred from a shape: without a codec, the value type's built-in
    // default applies, and a type without one reports its own diagnostic.
    let codec = codec.as_ref().map_or_else(
        || quote_spanned!(value.span()=> <#value as #krate::__private::DefaultCodec>::Codec),
        |codec| quote!(#codec),
    );
    let padding = padding.as_ref().map_or_else(
        || quote!(#krate::Padding::NONE),
        |padding| padding.to_tokens(krate),
    );
    let scope = own.scope();
    let scope = quote!(#krate::Recorded<#scope, #record_ty>);
    let keys = own.keys();
    let specs: Vec<_> = indexes.iter().map(|index| index.spec.clone()).collect();
    let items = seal_items(
        krate,
        id,
        &padding,
        &quote!(#value),
        &codec,
        &scope,
        &keys,
        &specs,
    );

    Some(quote! {
        #[doc = #doc]
        #vis struct #name;

        const _: () = {
            #[automatically_derived]
            impl #krate::Seal for #name {
                #items
            }
        };
    })
}
