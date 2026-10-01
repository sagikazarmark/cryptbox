//! Expands `#[derive(BlindIndexSpec)]`.

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{DeriveInput, Ident, Path, Type, spanned::Spanned};

use crate::attr::{Attrs, Errors, Key, required};

const KEYS: &[Key] = &[
    Key::Id,
    Key::Seal,
    Key::Bits,
    Key::Query,
    Key::Normalize,
    Key::Normalizer,
    Key::Project,
    Key::Crate,
];

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut errors = Errors::default();
    let mut attrs = Attrs::parse(&input.attrs, "cryptbox", KEYS, &mut errors);
    let krate = attrs.krate();
    let name = &input.ident;

    let id = required(
        attrs.id.take(),
        &attrs,
        Key::Id,
        name,
        "\"<uuid>\"",
        &mut errors,
    );
    let seal = required(
        attrs.seal.take(),
        &attrs,
        Key::Seal,
        name,
        "Seal",
        &mut errors,
    );
    let bits = required(
        attrs.bits.take(),
        &attrs,
        Key::Bits,
        name,
        "32",
        &mut errors,
    );
    let query = required(
        attrs.query.take(),
        &attrs,
        Key::Query,
        name,
        "str",
        &mut errors,
    );
    let normalize = required(
        attrs.normalize.take(),
        &attrs,
        Key::Normalize,
        name,
        "normalize_fn",
        &mut errors,
    );
    // Never derived from the normalizer's path: renaming a function does not
    // change stored indexes, and changing its body does.
    let normalizer_name = required(
        attrs.normalizer.take(),
        &attrs,
        Key::Normalizer,
        name,
        "\"email/1\"",
        &mut errors,
    );
    errors.finish()?;
    let (Some(id), Some(seal), Some(bits), Some(query), Some(normalize), Some(normalizer_name)) =
        (id, seal, bits, query, normalize, normalizer_name)
    else {
        unreachable!("missing keys are reported above");
    };

    // Mixed-site hygiene keeps the parameters from capturing the user's paths.
    let query_arg = Ident::new("query", Span::mixed_site());
    let value_arg = Ident::new("value", Span::mixed_site());

    // Span the calls on the user's paths so type errors point at the attribute.
    let normalize_query = quote_spanned!(normalize.span()=> #normalize(#query_arg));
    let normalize_value = normalize_value(&normalize, attrs.project.as_ref(), &seal, &value_arg);

    let normalized = quote! {
        ::core::result::Result<
            #krate::__private::Zeroizing<::std::vec::Vec<u8>>,
            #krate::BlindIndexError,
        >
    };
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        const _: () = {
            #[automatically_derived]
            impl #impl_generics #krate::BlindIndexSpec for #name #type_generics #where_clause {
                type Seal = #seal;
                const ID: #krate::IndexId = #krate::IndexId::from_u128(#id);
                const BITS: u16 = #bits;
                const NORMALIZER: &'static str = #normalizer_name;
                type Query = #query;

                fn normalize_query(#query_arg: &#query) -> #normalized {
                    #normalize_query
                }

                fn normalize_value(
                    #value_arg: &<#seal as #krate::Seal>::Value,
                ) -> #normalized {
                    #normalize_value
                }
            }
        };
    })
}

// Calls the normalizer on the sealed value, or on its projection.
fn normalize_value(
    normalize: &Path,
    project: Option<&Path>,
    seal: &Type,
    value_arg: &Ident,
) -> TokenStream {
    if let Some(project) = project {
        let projected = quote_spanned!(project.span()=> &#project(#value_arg));
        quote_spanned!(normalize.span()=> #normalize(#projected))
    } else {
        // Point a value that does not fit the normalizer at the `seal` key.
        let value = Ident::new("value", Span::mixed_site().located_at(seal.span()));
        quote_spanned!(normalize.span()=> #normalize(#value))
    }
}
