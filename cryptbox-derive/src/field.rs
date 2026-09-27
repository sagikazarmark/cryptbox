//! Expands `#[derive(Field)]`.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::{DeriveInput, spanned::Spanned};

use crate::attr::{Attrs, Errors, Key, required};

const KEYS: &[Key] = &[Key::Id, Key::Value, Key::Codec, Key::Padding, Key::Crate];

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut errors = Errors::default();
    let mut attrs = Attrs::parse(&input.attrs, KEYS, &mut errors);
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
    let value = required(
        attrs.value.take(),
        &attrs,
        Key::Value,
        name,
        "Type",
        &mut errors,
    );
    errors.finish()?;
    let (Some(id), Some(value)) = (id, value) else {
        unreachable!("missing keys are reported above");
    };

    // Never inferred from a shape: without a codec, the value type's `Plaintext`
    // default applies, and a type without one reports its own diagnostic.
    let codec = attrs.codec.map_or_else(
        || quote_spanned!(value.span()=> <#value as #krate::Plaintext>::Codec),
        |codec| quote!(#codec),
    );
    let padding = attrs.padding.map_or_else(
        || quote!(#krate::Padding::NONE),
        |padding| padding.to_tokens(&krate),
    );
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        const _: () = {
            #[automatically_derived]
            impl #impl_generics #krate::Field for #name #type_generics #where_clause {
                const ID: #krate::FieldId = #krate::FieldId::from_u128(#id);
                const PADDING: #krate::Padding = #padding;
                const RECORD: bool = false;
                type Value = #value;
                type Codec = #codec;
                type Binding = #krate::FieldOnly;
                type Indexes = ();
            }
        };
    })
}
