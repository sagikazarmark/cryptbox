//! Expands `#[derive(Plaintext)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::attr::{Attrs, Errors, Key};

const KEYS: &[Key] = &[Key::Codec, Key::Crate];

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut errors = Errors::default();
    let attrs = Attrs::parse(&input.attrs, KEYS, &mut errors);
    errors.finish()?;
    let krate = attrs.krate();
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    if let Some(codec) = &attrs.codec {
        return Ok(quote! {
            const _: () = {
                #[automatically_derived]
                impl #impl_generics #krate::Plaintext for #name #type_generics #where_clause {
                    type Codec = #codec;
                }
            };
        });
    }

    let inner = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Some(&fields.unnamed[0].ty),
            _ => None,
        },
        _ => None,
    };
    let Some(inner) = inner else {
        return Err(transparent_error(input));
    };

    // Transparent: the type is its own codec and stores exactly the bytes of its
    // inner value's default codec.
    Ok(quote! {
        const _: () = {
            #[automatically_derived]
            impl #impl_generics #krate::Plaintext for #name #type_generics #where_clause {
                type Codec = Self;
            }

            #[automatically_derived]
            impl #impl_generics #krate::Codec<Self> for #name #type_generics #where_clause {
                fn encode(
                    value: &Self,
                ) -> ::core::result::Result<
                    #krate::__private::Zeroizing<::std::vec::Vec<u8>>,
                    #krate::CodecError,
                > {
                    <<#inner as #krate::Plaintext>::Codec as #krate::Codec<#inner>>::encode(&value.0)
                }

                fn decode(bytes: &[u8]) -> ::core::result::Result<Self, #krate::CodecError> {
                    <<#inner as #krate::Plaintext>::Codec as #krate::Codec<#inner>>::decode(bytes)
                        .map(Self)
                }
            }
        };
    })
}

fn transparent_error(input: &DeriveInput) -> syn::Error {
    syn::Error::new(
        input.ident.span(),
        "missing `codec`: add `#[cryptbox(codec = Codec)]`; only a single-field tuple struct \
         defaults to its inner value's codec",
    )
}
