//! Expands `#[derive(Scope)]`.

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Data, DeriveInput, Fields, Ident, LitStr, Type, Visibility, spanned::Spanned};

use crate::attr::{Attrs, Errors, Key, UuidLiteral, required};

const KEYS: &[Key] = &[Key::IndexArgs, Key::Crate];

const PART_KEYS: &[Key] = &[Key::Part, Key::Keys, Key::Index];

// A record is bound through the seal scope, never as a declared part, so it can't be
// given a role.
const REJECTED: &[(Key, &str)] = &[(
    Key::Record,
    "a record is never a declared part, so it can't scope keys or blind indexes: \
     bind it with a seal scope of `cryptbox::Recorded<Scope, Id>`",
)];

/// What a part scopes; mirrors `cryptbox::PartRole`.
#[derive(Clone, Copy, PartialEq)]
enum Role {
    Keys,
    Index,
    Bound,
}

impl Role {
    /// Whether a query supplies the part: `keys` and `index` parts do.
    fn scopes_index(self) -> bool {
        self != Self::Bound
    }
}

/// One validated part: a struct field with its part ID and role.
struct Part<'a> {
    field: &'a syn::Field,
    ident: &'a Ident,
    id: UuidLiteral,
    role: Role,
}

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut errors = Errors::default();
    let attrs = Attrs::parse(&input.attrs, KEYS, &mut errors);
    let krate = attrs.krate();
    let name = &input.ident;

    let fields = struct_fields(input, &mut errors);
    let mut parts = parse_parts(&fields, &mut errors);
    // Which arguments a query needs depends on every part, so check it only
    // once they all parsed.
    errors = errors.check()?;
    let index_args = index_args(input, &attrs, &parts, &mut errors);
    errors.finish()?;

    // The derive sorts the parts, so fields can be declared in any order.
    // See ../../docs/wire-format.md#binding.
    let index_fields: Vec<_> = parts
        .iter()
        .filter(|part| part.role.scopes_index())
        .map(|part| part.field)
        .collect();
    parts.sort_by_key(|part| part.id.value());

    let specs = parts.iter().map(|part| {
        let ty = &part.field.ty;
        let id = &part.id;
        let constructor = match part.role {
            Role::Keys => quote!(keys),
            Role::Index => quote!(index),
            Role::Bound => quote!(bound),
        };
        let kind = quote_spanned!(ty.span()=> <#ty as #krate::PartType>::KIND);
        quote! {
            #krate::PartSpec::#constructor(#krate::PartId::from_u128(#id), #kind)
        }
    });
    let values = part_values(&krate, &quote!(self), parts.iter());

    let (index_args_type, index_args_item) = match index_args {
        IndexArgs::Unit => (quote!(()), None),
        IndexArgs::Scope => (quote!(Self), None),
        IndexArgs::Generated(args_name) => (
            quote!(#args_name),
            Some(index_args_struct(
                &input.vis,
                name,
                args_name,
                &index_fields,
            )),
        ),
    };
    let index_values = if matches!(index_args, IndexArgs::Unit) {
        quote! {
            fn index_values((): &()) -> #krate::PartValues<'_> {
                #krate::PartValues::new()
            }
        }
    } else {
        // Mixed-site hygiene keeps the parameter from capturing the user's names.
        let args = Ident::new("args", Span::mixed_site());
        let index_parts = parts.iter().filter(|part| part.role.scopes_index());
        let values = part_values(&krate, &quote!(#args), index_parts);
        quote! {
            fn index_values(#args: &#index_args_type) -> #krate::PartValues<'_> {
                #values
            }
        }
    };

    let from_index_values = from_index_values(&krate, &index_args_type, &index_args, &parts);
    let from_parts = from_parts(&krate, &parts);

    Ok(quote! {
        #index_args_item

        const _: () = {
            #[automatically_derived]
            impl #krate::Scope for #name {
                const PARTS: &'static [#krate::PartSpec] = &[#(#specs),*];
                type IndexArgs = #index_args_type;

                fn values(&self) -> #krate::PartValues<'_> {
                    #values
                }

                #index_values
            }

            #[automatically_derived]
            impl #krate::FromIndexValues for #name {
                #from_index_values
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
        let mut attrs = Attrs::parse_rejecting(&field.attrs, PART_KEYS, REJECTED, errors);
        // A rejected record is already reported; don't also ask for its part ID.
        if attrs.seen(Key::Record) {
            continue;
        }
        if let (Some(_), Some(index)) = (attrs.keys, attrs.index) {
            errors.push(syn::Error::new(
                index,
                "`keys` already scopes blind indexes: remove `index`",
            ));
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

        let role = match (attrs.keys, attrs.index) {
            (Some(_), _) => Role::Keys,
            (None, Some(_)) => Role::Index,
            (None, None) => Role::Bound,
        };
        parts.push(Part {
            field,
            ident,
            id,
            role,
        });
    }

    parts
}

/// The binding's `IndexArgs`.
enum IndexArgs<'a> {
    /// No `keys` or `index` parts: `()`.
    Unit,
    /// Every part is `keys` or `index`: the binding itself.
    Scope,
    /// The named struct the derive generates.
    Generated(&'a Ident),
}

fn index_args<'a>(
    input: &DeriveInput,
    attrs: &'a Attrs,
    parts: &[Part<'_>],
    errors: &mut Errors,
) -> IndexArgs<'a> {
    let name = &input.ident;
    let scoped = parts.iter().filter(|part| part.role.scopes_index()).count();
    let bound = parts.len() - scoped;

    match &attrs.index_args {
        Some(args_name) if args_name == name => {
            errors.push(syn::Error::new(
                args_name.span(),
                format!(
                    "`index_args` names the struct this derive generates, so it can't be `{name}` itself"
                ),
            ));
            IndexArgs::Unit
        }
        Some(args_name) if scoped == 0 => {
            errors.push(syn::Error::new(
                args_name.span(),
                "`index_args` needs a `keys` or `index` part: without one, the index arguments are `()`",
            ));
            IndexArgs::Unit
        }
        Some(args_name) => IndexArgs::Generated(args_name),
        // A query can't know bound-only parts, so they need their own arguments.
        None if scoped > 0 && bound > 0 => {
            if !attrs.seen(Key::IndexArgs) {
                errors.push(syn::Error::new(
                    name.span(),
                    "missing `index_args`: a query can't know the bound-only parts; \
                     add `#[cryptbox(index_args = Name)]` to generate the `keys` and `index` parts' struct",
                ));
            }
            IndexArgs::Unit
        }
        None if scoped > 0 => IndexArgs::Scope,
        None => IndexArgs::Unit,
    }
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

/// The generated index-arguments struct: the `keys` and `index` fields, in
/// declaration order, with their visibility and docs.
fn index_args_struct(
    vis: &Visibility,
    binding: &Ident,
    name: &Ident,
    fields: &[&syn::Field],
) -> TokenStream {
    let doc = LitStr::new(
        &format!("The index arguments of [`{binding}`]: its `keys` and `index` parts."),
        name.span(),
    );
    let fields = fields.iter().map(|field| {
        let docs = field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("doc"));
        let vis = &field.vis;
        let ident = &field.ident;
        let ty: &Type = &field.ty;
        quote!(#(#docs)* #vis #ident: #ty)
    });

    // Spanned on the name, so a clash with an existing item points at `index_args`.
    quote_spanned! {name.span()=>
        #[doc = #doc]
        #[derive(
            ::core::clone::Clone,
            ::core::fmt::Debug,
            ::core::hash::Hash,
            ::core::cmp::PartialEq,
            ::core::cmp::Eq,
        )]
        #vis struct #name {
            #(#fields),*
        }
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

/// The body of `FromIndexValues`: one value per `keys` and `index` part, in
/// sorted `parts` order, read back into the index arguments.
fn from_index_values(
    krate: &syn::Path,
    index_args_type: &TokenStream,
    index_args: &IndexArgs<'_>,
    parts: &[Part<'_>],
) -> TokenStream {
    // Mixed-site hygiene keeps the parameter and bindings from capturing the user's names.
    let values = Ident::new("values", Span::mixed_site());
    let invalid = quote!(::core::result::Result::Err(#krate::Error::InvalidBinding));
    let (patterns, fields): (Vec<_>, Vec<_>) = parts
        .iter()
        .filter(|part| part.role.scopes_index())
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
    let args = match index_args {
        IndexArgs::Unit => quote!(()),
        IndexArgs::Scope | IndexArgs::Generated(_) => {
            quote!(#index_args_type { #(#fields),* })
        }
    };

    quote! {
        fn from_index_values(
            #values: &[#krate::PartValue<'_>],
        ) -> ::core::result::Result<#index_args_type, #krate::Error> {
            match #values {
                [#(#patterns),*] => ::core::result::Result::Ok(#args),
                _ => #invalid,
            }
        }
    }
}
