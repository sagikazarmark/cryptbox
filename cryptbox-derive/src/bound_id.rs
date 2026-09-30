//! Expands `#[derive(BoundId)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::attr::{Attrs, Errors, Key, required};

const KEYS: &[Key] = &[Key::Kind, Key::Crate];

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut errors = Errors::default();
    let mut attrs = Attrs::parse(&input.attrs, "cryptbox", KEYS, &mut errors);
    let krate = attrs.krate();
    let name = &input.ident;

    let kind = required(
        attrs.kind.take(),
        &attrs,
        Key::Kind,
        name,
        "\"<uuid>\"",
        &mut errors,
    );
    if !input.generics.params.is_empty() {
        errors.push(syn::Error::new_spanned(
            &input.generics,
            "`BoundId` can't be derived for a generic type: its kind is persistent schema",
        ));
    }
    let inner = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Some(&fields.unnamed[0].ty),
            _ => None,
        },
        _ => None,
    };
    if inner.is_none() {
        errors.push(syn::Error::new(
            name.span(),
            "`BoundId` is derived for a newtype over one ID, such as `struct OrgId(Uuid);`",
        ));
    }
    errors.finish()?;
    let (Some(kind), Some(inner)) = (kind, inner) else {
        unreachable!("missing keys and shapes are reported above");
    };

    Ok(quote! {
        const _: () = {
            #[automatically_derived]
            impl #krate::PartType for #name {
                const KIND: #krate::PartKind = <#inner as #krate::PartType>::KIND;

                fn part_value(&self) -> #krate::PartValue<'_> {
                    <#inner as #krate::PartType>::part_value(&self.0)
                }

                fn from_part_value(
                    value: #krate::PartValue<'_>,
                ) -> ::core::result::Result<Self, #krate::Error> {
                    <#inner as #krate::PartType>::from_part_value(value).map(Self)
                }
            }

            #[automatically_derived]
            impl #krate::BoundId for #name {
                const KIND_ID: #krate::PartId = #krate::PartId::from_u128(#kind);
            }
        };
    })
}
