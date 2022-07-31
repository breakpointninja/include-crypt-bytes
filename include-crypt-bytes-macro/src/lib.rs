use proc_macro::TokenStream;
use quote::quote;
use std::fs;
use syn::{
    parse::{Parse, ParseStream, Result},
    parse_macro_input,
    token::Comma,
    Expr, LitStr,
};

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
        include_crypt_bytes_cipher::encrypt_bytes(&bytes, password.as_bytes())
            .expect("Could not encrypt message");
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

        Ok(ObfuscateArgs { path })
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

    let (ciphertext, nonce, salt) = include_crypt_bytes_cipher::encrypt_bytes(&bytes, &password)
        .expect("Could not encrypt message");

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
