use darling::{
    ast::{self, Fields},
    FromDeriveInput, FromField, FromVariant,
};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, DeriveInput, Expr, Generics, Ident, Index, Path};

enum Operation {
    Size,
    Encode,
    Decode,
}

impl Operation {
    fn path(&self) -> Path {
        match self {
            Operation::Size => parse_quote! { aws_mls_codec::MlsSize },
            Operation::Encode => parse_quote! { aws_mls_codec::MlsEncode },
            Operation::Decode => parse_quote! { aws_mls_codec::MlsDecode },
        }
    }

    fn call(&self) -> TokenStream {
        match self {
            Operation::Size => quote! { mls_encoded_len },
            Operation::Encode => quote! { mls_encode },
            Operation::Decode => quote! { mls_decode },
        }
    }

    fn extras(&self) -> TokenStream {
        match self {
            Operation::Size => quote! {},
            Operation::Encode => quote! { , &mut writer },
            Operation::Decode => quote! { reader },
        }
    }

    fn is_result(&self) -> bool {
        match self {
            Operation::Size => false,
            Operation::Encode => true,
            Operation::Decode => true,
        }
    }
}

#[derive(Debug, FromField)]
#[darling(attributes(mls_codec))]
struct MlsFieldReceiver {
    ident: Option<Ident>,
    with: Option<Path>,
}

impl MlsFieldReceiver {
    pub fn call_tokens(&self, index: Index) -> TokenStream {
        if let Some(ref ident) = self.ident {
            quote! { &self.#ident }
        } else {
            quote! { &self.#index }
        }
    }

    pub fn name(&self, index: Index) -> TokenStream {
        if let Some(ref ident) = self.ident {
            quote! {#ident: }
        } else {
            quote! { #index: }
        }
    }
}

#[derive(Debug, FromVariant)]
#[darling(attributes(mls_codec))]
struct MlsVariantReceiver {
    ident: Ident,
    discriminant: Option<Expr>,
    fields: ast::Fields<MlsFieldReceiver>,
}

#[derive(FromDeriveInput)]
#[darling(attributes(mls_codec))]
struct MlsInputReceiver {
    ident: Ident,
    generics: Generics,
    data: ast::Data<MlsVariantReceiver, MlsFieldReceiver>,
}

impl MlsInputReceiver {
    fn handle_input(&self, operation: Operation) -> TokenStream {
        match self.data {
            ast::Data::Struct(ref s) => struct_impl(s, operation),
            ast::Data::Enum(ref e) => enum_impl(&self.ident, e, operation),
        }
    }
}

fn enum_impl(ident: &Ident, variants: &[MlsVariantReceiver], operation: Operation) -> TokenStream {
    let handle_error = operation.is_result().then_some(quote! { ? });
    let path = operation.path();
    let call = operation.call();
    let extras = operation.extras();
    let enum_name = &ident;

    if matches!(operation, Operation::Decode) {
        let cases = variants.iter().map(|variant| {
            let variant_name = &variant.ident;

            // TODO: Calculate discriminant and support integers that are assumed types like u16,
            // u32 etc based on repr()
            let discriminant = &variant
                .discriminant
                .clone()
                .expect("Enum discriminants must be explicitly defined");

            // TODO: Support more than 1 field
            match variant.fields.len() {
                0 => quote! { #discriminant => Ok(#enum_name::#variant_name), },
                1 =>{
                    let path = variant.fields.fields[0].with.as_ref().unwrap_or(&path);
                    quote! { #discriminant => Ok(#enum_name::#variant_name(#path::#call(#extras) #handle_error)), }
                },
                _ => panic!("Enum discriminants with more than 1 field are not currently supported")
            }
        });

        return quote! {
            let discriminant = #path::#call(#extras)#handle_error;

            match discriminant {
                #(#cases)*
                _ => Err(aws_mls_codec::Error::UnsupportedEnumDiscriminant),
            }
        };
    }

    let cases = variants.iter().map(|variant| {
        let variant_name = &variant.ident;

        let discriminant = &variant
            .discriminant
            .clone()
            .expect("Enum discriminants must be explicitly defined");

        let (parameter, field) = if variant.fields.is_empty() {
            (None, None)
        } else {
            let path = variant.fields.fields[0].with.as_ref().unwrap_or(&path);

            let start = match operation {
                Operation::Size => Some(quote! { + }),
                Operation::Encode => Some(quote! {;}),
                Operation::Decode => None,
            };

            (
                Some(quote! {(ref val)}),
                Some(quote! { #start #path::#call (val #extras) #handle_error }),
            )
        };

        let discrim = quote! { #path::#call (&#discriminant #extras) #handle_error };

        quote! { #enum_name::#variant_name #parameter => { #discrim #field }}
    });

    let enum_impl = quote! {
        match self {
            #(#cases)*
        }
    };

    if operation.is_result() {
        quote! {
            Ok(#enum_impl)
        }
    } else {
        enum_impl
    }
}

fn struct_impl(s: &Fields<MlsFieldReceiver>, operation: Operation) -> TokenStream {
    let recurse = s.fields.iter().enumerate().map(|(index, field)| {
        let (call_tokens, field_name) = match operation {
            Operation::Size | Operation::Encode => {
                (field.call_tokens(Index::from(index)), quote! {})
            }
            Operation::Decode => (quote! {}, field.name(Index::from(index))),
        };

        let handle_error = operation.is_result().then_some(quote! { ? });
        let path = field.with.clone().unwrap_or(operation.path());
        let call = operation.call();
        let extras = operation.extras();

        quote! {
           #field_name #path::#call (#call_tokens #extras) #handle_error
        }
    });

    match operation {
        Operation::Size => quote! { 0 #(+ #recurse)* },
        Operation::Encode => quote! { #(#recurse;)* Ok(()) },
        Operation::Decode => quote! { Ok(Self { #(#recurse,)* }) },
    }
}

fn derive_impl<F>(
    input: proc_macro::TokenStream,
    trait_name: TokenStream,
    function_def: TokenStream,
    internals: F,
) -> proc_macro::TokenStream
where
    F: FnOnce(&MlsInputReceiver) -> TokenStream,
{
    let input = parse_macro_input!(input as DeriveInput);
    let input = MlsInputReceiver::from_derive_input(&input).unwrap();

    let name = &input.ident;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Generate an expression to sum up the heap size of each field.
    let function_impl = internals(&input);

    let expanded = quote! {
        // The generated impl.
        impl #impl_generics #trait_name for #name #ty_generics #where_clause {
            #function_def {
                #function_impl
            }
        }
    };

    // Hand the output tokens back to the compiler.
    proc_macro::TokenStream::from(expanded)
}

#[proc_macro_derive(MlsSize, attributes(mls_codec))]
pub fn derive_size(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let trait_name = quote! { aws_mls_codec::MlsSize };
    let function_def = quote! {fn mls_encoded_len(&self) -> usize };

    derive_impl(input, trait_name, function_def, |input| {
        input.handle_input(Operation::Size)
    })
}

#[proc_macro_derive(MlsEncode, attributes(mls_codec))]
pub fn derive_encode(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let trait_name = quote! { aws_mls_codec::MlsEncode };

    let function_def = quote! { fn mls_encode<W: aws_mls_codec::Writer>(&self, mut writer: W) -> Result<(), aws_mls_codec::Error> };

    derive_impl(input, trait_name, function_def, |input| {
        input.handle_input(Operation::Encode)
    })
}

#[proc_macro_derive(MlsDecode, attributes(mls_codec))]
pub fn derive_decode(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let trait_name = quote! { aws_mls_codec::MlsDecode };

    let function_def =
        quote! { fn mls_decode(reader: &mut &[u8]) -> Result<Self, aws_mls_codec::Error> };

    derive_impl(input, trait_name, function_def, |input| {
        input.handle_input(Operation::Decode)
    })
}
