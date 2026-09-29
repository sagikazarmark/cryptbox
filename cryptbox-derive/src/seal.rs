//! Expands `#[derive(Seal)]`.

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Data, DeriveInput, Fields, Member, Type, spanned::Spanned};

use crate::attr::{Attrs, Errors, Key, required};

const KEYS: &[Key] = &[
    Key::Id,
    Key::Value,
    Key::Codec,
    Key::Transparent,
    Key::Padding,
    Key::Binding,
    Key::Record,
    Key::Indexes,
    Key::Crate,
];

/// What the seal's values are, and how they are encoded.
enum Form<'a> {
    /// A unit struct over a separate value type.
    Marker { value: Type, codec: TokenStream },
    /// The type is its own value, encoded whole by `codec`.
    SelfValued { codec: Type },
    /// The type is its own value, stored as its single field.
    Transparent {
        member: Member,
        inner: &'a Type,
        codec: TokenStream,
    },
}

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
    let form = form(input, &mut attrs, &mut errors);
    errors.finish()?;
    let (Some(id), Some(form)) = (id, form) else {
        unreachable!("missing keys are reported above");
    };

    let padding = attrs.padding.map_or_else(
        || quote!(#krate::Padding::NONE),
        |padding| padding.to_tokens(&krate),
    );
    let record = attrs.record.is_some();
    let binding = attrs
        .binding
        .map_or_else(|| quote!(#krate::FieldOnly), |binding| quote!(#binding));
    let indexes = attrs.indexes.unwrap_or_default();
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let (value, codec, adapter) = match form {
        Form::Marker { value, codec } => (quote!(#value), codec, None),
        Form::SelfValued { codec } => (quote!(Self), quote!(#codec), None),
        Form::Transparent {
            member,
            inner,
            codec,
        } => {
            let inner_codec = quote!(<#codec as #krate::Codec<#inner>>);
            let wrap = match &member {
                Member::Named(field) => quote!(|inner| Self { #field: inner }),
                Member::Unnamed(_) => quote!(Self),
            };
            // The seal is its own codec: no crate-provided adapter can wrap or
            // unwrap it without `From` or `Deref`, which the derive never adds.
            let adapter = quote! {
                #[automatically_derived]
                impl #impl_generics #krate::Codec<Self> for #name #type_generics #where_clause {
                    const ID: &'static str = #inner_codec::ID;

                    fn encode(
                        value: &Self,
                    ) -> ::core::result::Result<
                        #krate::__private::Zeroizing<::std::vec::Vec<u8>>,
                        #krate::CodecError,
                    > {
                        #inner_codec::encode(&value.#member)
                    }

                    fn decode(bytes: &[u8]) -> ::core::result::Result<Self, #krate::CodecError> {
                        #inner_codec::decode(bytes).map(#wrap)
                    }
                }
            };
            (quote!(Self), quote!(Self), Some(adapter))
        }
    };

    Ok(quote! {
        const _: () = {
            #[automatically_derived]
            impl #impl_generics #krate::Seal for #name #type_generics #where_clause {
                const ID: #krate::SealId = #krate::SealId::from_u128(#id);
                const PADDING: #krate::Padding = #padding;
                const RECORD: bool = #record;
                type Value = #value;
                type Codec = #codec;
                type Binding = #binding;
                type Indexes = (#(#indexes,)*);
            }

            #adapter
        };
    })
}

/// Reads the seal's form from the type's shape and its `value`, `codec`, and
/// `transparent` keys. The shape decides only whether the type is its own
/// value; the codec is always stated or a built-in default, never inferred.
fn form<'a>(input: &'a DeriveInput, attrs: &mut Attrs, errors: &mut Errors) -> Option<Form<'a>> {
    let name = &input.ident;
    let krate = attrs.krate();
    let codec = attrs.codec.take();
    let transparent = attrs.transparent;

    if matches!(&input.data, Data::Struct(data) if matches!(data.fields, Fields::Unit)) {
        if let Some(span) = transparent {
            errors.push(syn::Error::new(
                span,
                "`transparent` needs a struct with exactly one field; a unit struct is a \
                 marker over its `value` type",
            ));
        }
        let value = required(attrs.value.take(), attrs, Key::Value, name, "Type", errors)?;
        // Without a codec, the value type's built-in default applies, and a type
        // without one reports its own diagnostic.
        let codec = codec.map_or_else(
            || quote_spanned!(value.span()=> <#value as #krate::Plaintext>::Codec),
            |codec| quote!(#codec),
        );
        return Some(Form::Marker { value, codec });
    }

    if let Some(value) = attrs.value.take() {
        errors.push(syn::Error::new(
            value.span(),
            "a type with fields is its own value: remove `value`, or declare the seal as a \
             unit struct to seal a separate value type",
        ));
        return None;
    }

    if let Some(span) = transparent {
        let Some((member, inner)) = single_field(input) else {
            errors.push(syn::Error::new(
                span,
                "`transparent` needs a struct with exactly one field",
            ));
            return None;
        };
        let codec = codec.map_or_else(
            || quote_spanned!(inner.span()=> <#inner as #krate::Plaintext>::Codec),
            |codec| quote!(#codec),
        );
        return Some(Form::Transparent {
            member,
            inner,
            codec,
        });
    }

    let Some(codec) = codec else {
        // An invalid `codec` or `transparent` is already reported.
        if !attrs.seen(Key::Codec) && !attrs.seen(Key::Transparent) {
            errors.push(syn::Error::new(
                name.span(),
                "missing `codec`: a type with fields is its own value, so name how it is \
                 encoded with `#[cryptbox(codec = Codec)]`, or store its single field with \
                 `#[cryptbox(transparent)]`",
            ));
        }
        return None;
    };

    Some(Form::SelfValued { codec })
}

/// The member and type of a struct's only field.
fn single_field(input: &DeriveInput) -> Option<(Member, &Type)> {
    let Data::Struct(data) = &input.data else {
        return None;
    };
    let mut fields = data.fields.iter();
    let (Some(field), None) = (fields.next(), fields.next()) else {
        return None;
    };
    let member = field.ident.clone().map_or_else(
        || {
            Member::Unnamed(syn::Index {
                index: 0,
                span: Span::call_site(),
            })
        },
        Member::Named,
    );

    Some((member, &field.ty))
}
