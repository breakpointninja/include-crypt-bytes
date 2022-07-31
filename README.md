# include-crypt-bytes

Procedural macro to embed encrypted binary data in compiled binaries.

The macro works similarly to [`std::include_str`], but instead of embedding the UTF-8
string, it embeds encrypted `[u8]` array. Encryption uses the [chacha20poly1305][1] crate.

## Examples

```rust
// CONFIG_PASSWORD is the environment variable set to the
// string used to encrypt the contents of the file config.toml
// at compile time
//
// `password` is the variable used to decrypt the embedded data
// at runtime.
let file_bytes = include_bytes_crypt!(
                    "config.toml",
                    password.as_bytes(),
                    "CONFIG_PASSWORD");
```

Sometimes, its useful just to obfuscate the embedded data. In that case just the file name is required

```rust
// A random password is generated at compiled time
let file_bytes = include_bytes_obfuscate!("config.toml");
```

[1]: https://docs.rs/chacha20poly1305

License: MIT OR Apache-2.0
