use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::fs;
use syn::{
    fold::{self, Fold},
    parse::{Parse, ParseStream, Result},
    parse_macro_input, parse_quote,
    token::Comma,
    FnArg, ItemFn, LitStr, Pat, PathSegment, ReturnType, Signature, Type, Visibility, Expr
};

struct Args {
    get_type: bool,
    captured_type: Option<Type>,
}

impl Parse for Args {
    fn parse(_input: ParseStream) -> Result<Self> {
        Ok(Args {
            get_type: false,
            captured_type: None,
        })
    }
}

impl Fold for Args {
    fn fold_signature(&mut self, i: Signature) -> Signature {
        let mut i = fold::fold_signature(self, i);

        if let Some(captured) = self.captured_type.take() {
            if let ReturnType::Type(_, ty) = &mut i.output {
                *ty = Box::new(captured)
            }
        }

        i
    }

    fn fold_path_segment(&mut self, i: PathSegment) -> PathSegment {
        if i.ident == "ImapResult" {
            self.get_type = true;
        }

        fold::fold_path_segment(self, i)
    }

    fn fold_type(&mut self, i: Type) -> Type {
        if self.get_type {
            self.captured_type = Some(i.clone());
            self.get_type = false;
        }

        fold::fold_type(self, i)
    }
}

#[proc_macro_attribute]
pub fn retry_imap(metadata: TokenStream, input: TokenStream) -> TokenStream {
    // returing a simple TokenStream for Struct
    let mut input_fn = parse_macro_input!(input as ItemFn);
    let mut args = parse_macro_input!(metadata as Args);

    let input_fn_with_underscore = {
        let mut with_undscor = input_fn.clone();
        with_undscor.sig.ident = format_ident!("__{}", &with_undscor.sig.ident);
        with_undscor.vis = Visibility::Inherited;
        with_undscor
    };

    input_fn.sig = args.fold_signature(input_fn.sig.clone());
    let mut input_args = vec![];

    for arg in input_fn.sig.inputs.iter() {
        match arg {
            FnArg::Receiver(_) => (),
            FnArg::Typed(pt) => {
                if let Pat::Ident(pi) = pt.pat.as_ref() {
                    input_args.push(pi.ident.clone());
                }
            }
        }
    }

    let input_args_ref = input_args.iter();
    let fn_sig_undrscor = &input_fn_with_underscore.sig.ident;

    input_fn.block = parse_quote!(
        {
            let mut backoff = ExpBackoff::new(&self.username);

            loop {
                let er = match self. #fn_sig_undrscor (#(#input_args_ref , )*).await {
                    Err(e) => e,
                    Ok(r) => return r,
                };
                log::error!("Failed IMAP: {:?}", er);
                self.refresh();
                backoff.wait().await;
            }
        }
    );

    TokenStream::from(quote!(
        #input_fn_with_underscore

        #input_fn
    ))
}

struct CryptArgs {
    path: String,
    password_exp: Expr,
    password_env_var: String,
}

impl Parse for CryptArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let path = input.parse::<LitStr>()?.value();
        input.parse::<Comma>()?;
        let password_ident: Expr = input.parse()?;
        input.parse::<Comma>()?;
        let password_env_var = input.parse::<LitStr>()?.value();

        Ok(CryptArgs {
            path,
            password_exp: password_ident,
            password_env_var,
        })
    }
}

#[proc_macro]
pub fn include_bytes_crypt(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as CryptArgs);

    let bytes = fs::read(&args.path)
        .unwrap_or_else(|_| panic!("Could not read file at path {}", &args.path));
    let password = std::env::var(&args.password_env_var)
        .unwrap_or_else(|_| panic!("Could not get password from env {}", &args.password_env_var));
    let (ciphertext, nonce, salt) =
        include_crypt_bytes_cipher::encrypt_bytes(&bytes, password.as_bytes()).expect("Could not encrypt message");
    let password_exp = &args.password_exp;

    let ciphertext_length = ciphertext.len();
    let nonce_length = nonce.len();
    let salt_length = salt.len();

    let q = quote!(
        {
            const ciphertext: [u8; #ciphertext_length] = [ #(#ciphertext , )* ] ;
            const nonce:      [u8; #nonce_length]      = [ #(#nonce      , )* ] ;
            const salt:       [u8; #salt_length]       = [ #(#salt       , )* ] ;

            include_crypt_bytes::decrypt_bytes(&ciphertext, #password_exp, &nonce, &salt)
        }
    );

    TokenStream::from(q)
}

struct ObfuscateArgs {
    path: String,
}

impl Parse for ObfuscateArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let path = input.parse::<LitStr>()?.value();

        Ok(ObfuscateArgs {
            path,
        })
    }
}

#[proc_macro]
pub fn include_bytes_obfuscate(input: TokenStream) -> TokenStream {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let args = parse_macro_input!(input as ObfuscateArgs);

    let bytes = fs::read(&args.path)
        .unwrap_or_else(|_| panic!("Could not read file at path {}", &args.path));

    const PASSWORD_LENGTH: usize = 32;
    let mut password = [0u8; PASSWORD_LENGTH];
    OsRng.fill_bytes(&mut password);

    let (ciphertext, nonce, salt) =
        include_crypt_bytes_cipher::encrypt_bytes(&bytes, &password).expect("Could not encrypt message");

    let ciphertext_length = ciphertext.len();
    let nonce_length = nonce.len();
    let salt_length = salt.len();

    let q = quote!(
        {
            const ciphertext: [u8; #ciphertext_length] = [ #(#ciphertext , )* ] ;
            const nonce:      [u8; #nonce_length]      = [ #(#nonce      , )* ] ;
            const salt:       [u8; #salt_length]       = [ #(#salt       , )* ] ;
            const password:   [u8; #PASSWORD_LENGTH]   = [ #(#password   , )* ] ;

            include_crypt_bytes::decrypt_bytes(&ciphertext, &password, &nonce, &salt)
        }
    );

    TokenStream::from(q)
}
