//! Expands `#[derive(Scope)]`.

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Data, DeriveInput, Fields, Ident, spanned::Spanned};

use crate::attr::{Attrs, Errors, Key, UuidLiteral, required};

const KEYS: &[Key] = &[Key::Crate];

// A blind index names its own scope now (ADR-0009).
const REJECTED: &[(Key, &str)] = &[(
    Key::IndexArgs,
    "`index_args` is gone: a blind index names its own scope, a view of this one, \
     with `scope = …`",
)];

const PART_KEYS: &[Key] = &[Key::Part];

// A record is bound through the seal scope, never as a declared part; and parts
// have no roles: views of the scope say what else a part scopes (ADR-0009).
const PART_REJECTED: &[(Key, &str)] = &[
    (
        Key::Record,
        "a record is never a declared part: bind it with a seal scope of \
         `cryptbox::Recorded<Scope, Id>`",
    ),
    (
        Key::Keys,
        "parts have no roles: name the parts that key custody follows on the seal, \
         with `keys = View`, a view of this scope",
    ),
    (
        Key::Index,
        "parts have no roles: a blind index names the parts it is partitioned by \
         with its own scope, `scope = …`, a view of this one",
    ),
];

/// One validated part: a struct field with its part ID.
struct Part<'a> {
    field: &'a syn::Field,
    ident: &'a Ident,
    id: UuidLiteral,
}

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut errors = Errors::default();
    let attrs = Attrs::parse_rejecting(&input.attrs, KEYS, REJECTED, &mut errors);
    let krate = attrs.krate();
    let name = &input.ident;

    let fields = struct_fields(input, &mut errors);
    let mut parts = parse_parts(&fields, &mut errors);
    errors.finish()?;

    // The derive sorts the parts, so fields can be declared in any order.
    // See ../../docs/wire-format.md#binding.
    parts.sort_by_key(|part| part.id.value());

    let specs = parts.iter().map(|part| {
        let ty = &part.field.ty;
        let id = &part.id;
        let kind = quote_spanned!(ty.span()=> <#ty as #krate::PartType>::KIND);
        quote! {
            #krate::PartSpec::new(#krate::PartId::from_u128(#id), #kind)
        }
    });
    let values = part_values(&krate, &quote!(self), parts.iter());
    let from_parts = from_parts(&krate, &parts);

    Ok(quote! {
        const _: () = {
            #[automatically_derived]
            impl #krate::Scope for #name {
                const PARTS: &'static [#krate::PartSpec] = &[#(#specs),*];

                fn values(&self) -> #krate::PartValues<'_> {
                    #values
                }
            }

            #[automatically_derived]
            impl #krate::FromParts for #name {
                #from_parts
            }
        };
    })
}

/// The named fields of a non-generic struct, at least one; each is one part.
fn struct_fields<'a>(input: &'a DeriveInput, errors: &mut Errors) -> Vec<&'a syn::Field> {
    if !input.generics.params.is_empty() {
        errors.push(syn::Error::new_spanned(
            &input.generics,
            "`Scope` can't be derived for a generic type: its parts are persistent schema",
        ));
    }

    let Data::Struct(data) = &input.data else {
        errors.push(syn::Error::new(
            input.ident.span(),
            "`Scope` can only be derived for a struct",
        ));
        return Vec::new();
    };

    match &data.fields {
        Fields::Named(fields) if !fields.named.is_empty() => fields.named.iter().collect(),
        Fields::Named(_) | Fields::Unit => {
            errors.push(syn::Error::new(
                input.ident.span(),
                "a scope needs at least one part: use `()` for none",
            ));
            Vec::new()
        }
        Fields::Unnamed(fields) => {
            errors.push(syn::Error::new_spanned(
                fields,
                "`Scope` needs named fields: each field names one part",
            ));
            Vec::new()
        }
    }
}

/// Parses each field's part, rejecting nil and duplicate part IDs.
fn parse_parts<'a>(fields: &[&'a syn::Field], errors: &mut Errors) -> Vec<Part<'a>> {
    let mut parts: Vec<Part<'a>> = Vec::new();

    for field in fields {
        let Some(ident) = &field.ident else { continue };
        let mut attrs = Attrs::parse_rejecting(&field.attrs, PART_KEYS, PART_REJECTED, errors);
        // A rejected record or role is already reported; don't also ask for more.
        if attrs.seen(Key::Record) || attrs.seen(Key::Keys) || attrs.seen(Key::Index) {
            continue;
        }
        let Some(id) = required(
            attrs.part.take(),
            &attrs,
            Key::Part,
            ident,
            "\"<uuid>\"",
            errors,
        ) else {
            continue;
        };

        if id.value() == 0 {
            errors.push(syn::Error::new(
                id.span(),
                "binding part IDs must not be nil",
            ));
            continue;
        }
        if let Some(other) = parts.iter().find(|part| part.id.value() == id.value()) {
            errors.push(syn::Error::new(
                id.span(),
                format!("duplicate part ID: `{}` already declares it", other.ident),
            ));
            continue;
        }

        parts.push(Part { field, ident, id });
    }

    parts
}

/// `PartValues` of `parts`, read from `source` in the given order.
fn part_values<'a>(
    krate: &syn::Path,
    source: &TokenStream,
    parts: impl Iterator<Item = &'a Part<'a>>,
) -> TokenStream {
    let values: Vec<_> = parts
        .map(|part| {
            let ty = &part.field.ty;
            let ident = part.ident;
            quote_spanned!(ty.span()=> <#ty as #krate::PartType>::part_value(&#source.#ident))
        })
        .collect();

    if values.is_empty() {
        quote!(#krate::PartValues::new())
    } else {
        quote!(#krate::PartValues::from([#(#values),*]))
    }
}

/// The body of `FromParts`: one value per part, in sorted `parts` order, read
/// back into the struct.
fn from_parts(krate: &syn::Path, parts: &[Part<'_>]) -> TokenStream {
    // Mixed-site hygiene keeps the parameter and bindings from capturing the user's names.
    let values = Ident::new("values", Span::mixed_site());
    let (patterns, fields): (Vec<_>, Vec<_>) = parts
        .iter()
        .enumerate()
        .map(|(position, part)| {
            let value = Ident::new(&format!("value{position}"), Span::mixed_site());
            let ty = &part.field.ty;
            let ident = part.ident;
            let field = quote_spanned! {ty.span()=>
                #ident: <#ty as #krate::PartType>::from_part_value(*#value)?
            };
            (value, field)
        })
        .unzip();

    quote! {
        fn from_parts(
            #values: &[#krate::PartValue<'_>],
        ) -> ::core::result::Result<Self, #krate::Error> {
            match #values {
                [#(#patterns),*] => ::core::result::Result::Ok(Self { #(#fields),* }),
                _ => ::core::result::Result::Err(#krate::Error::InvalidBinding),
            }
        }
    }
}
