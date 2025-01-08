### Features:
* Add openssl for parsing certificate and getting Public Key from it;
* Delete `cubix` and `salvo` dependencies;
* Delete getters;
* Support decoding multiple jsonwebtoken algos;
* Add JWT validation;
* Write Casdoor OAuth2 client for getting access_token;

This lib is not production ready, cause it use [OAuth2 Release candidate](https://github.com/ramosbugs/oauth2-rs/tree/5.0.0-rc.1) with big API update.
Read more [here](https://github.com/ramosbugs/oauth2-rs/blob/main/UPGRADE.md).

Also, I started it for closing [RUSTSEC-2024-0421](https://rustsec.org/advisories/RUSTSEC-2024-0421.html).

# casdoor-sdk-rust

A [Casdoor](https://github.com/casdoor/casdoor) SDK (contain APIs) with more complete interfaces and better usability.

[![GitHub last commit](https://img.shields.io/github/last-commit/DMoscicki/casdoor-sdk-rust)](https://github.com/DMoscicki/casdoor-sdk-rust/commits/main)
[![Crates.io](https://img.shields.io/crates/v/casdoor-sdk-rust.svg)](https://crates.io/crates/casdoor-sdk-rust)
[![Docs](https://docs.rs/casdoor-sdk-rust/badge.svg)](https://docs.rs/casdoor-sdk-rust)
[![CI](https://github.com/DMoscicki/casdoor-sdk-rust/actions/workflows/security_audit.yml/badge.svg)](https://github.com/DMoscicki/casdoor-sdk-rust/actions/workflows/security_audit.yml)

## Install

Run the following Cargo command in your project directory:

```sh
cargo add casdoor-sdk-rust
```

Or add the following line to your Cargo.toml:

```toml
casdoor-sdk-rust = "1"
```

## Example

```rust
#[cfg(test)]
mod tests {
    use casdoor-sdk-rust::*;

    #[test]
    fn example() {
        let endpoint = "http://localhost:8000";
        let client_id = "0e6ad201d317fb74fe9d";
        let client_secret = "1fc847b0fdb3cb3f067c15ee383dee6213bd3fde";
        let certificate = r###"
-----BEGIN CERTIFICATE-----
MIIE+TCCAuGgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMDYxHTAbBgNVBAoTFENh
c2Rvb3IgT3JnYW5pemF0aW9uMRUwEwYDVQQDEwxDYXNkb29yIENlcnQwHhcNMjEx
MDE1MDgxMTUyWhcNNDExMDE1MDgxMTUyWjA2MR0wGwYDVQQKExRDYXNkb29yIE9y
Z2FuaXphdGlvbjEVMBMGA1UEAxMMQ2FzZG9vciBDZXJ0MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAsInpb5E1/ym0f1RfSDSSE8IR7y+lw+RJjI74e5ej
rq4b8zMYk7HeHCyZr/hmNEwEVXnhXu1P0mBeQ5ypp/QGo8vgEmjAETNmzkI1NjOQ
CjCYwUrasO/f/MnI1C0j13vx6mV1kHZjSrKsMhYY1vaxTEP3+VB8Hjg3MHFWrb07
uvFMCJe5W8+0rKErZCKTR8+9VB3janeBz//zQePFVh79bFZate/hLirPK0Go9P1g
OvwIoC1A3sarHTP4Qm/LQRt0rHqZFybdySpyWAQvhNaDFE7mTstRSBb/wUjNCUBD
PTSLVjC04WllSf6Nkfx0Z7KvmbPstSj+btvcqsvRAGtvdsB9h62Kptjs1Yn7GAuo
I3qt/4zoKbiURYxkQJXIvwCQsEftUuk5ew5zuPSlDRLoLByQTLbx0JqLAFNfW3g/
pzSDjgd/60d6HTmvbZni4SmjdyFhXCDb1Kn7N+xTojnfaNkwep2REV+RMc0fx4Gu
hRsnLsmkmUDeyIZ9aBL9oj11YEQfM2JZEq+RVtUx+wB4y8K/tD1bcY+IfnG5rBpw
IDpS262boq4SRSvb3Z7bB0w4ZxvOfJ/1VLoRftjPbLIf0bhfr/AeZMHpIKOXvfz4
yE+hqzi68wdF0VR9xYc/RbSAf7323OsjYnjjEgInUtRohnRgCpjIk/Mt2Kt84Kb0
wn8CAwEAAaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAn2lf
DKkLX+F1vKRO/5gJ+Plr8P5NKuQkmwH97b8CS2gS1phDyNgIc4/LSdzuf4Awe6ve
C06lVdWSIis8UPUPdjmT2uMPSNjwLxG3QsrimMURNwFlLTfRem/heJe0Zgur9J1M
8haawdSdJjH2RgmFoDeE2r8NVRfhbR8KnCO1ddTJKuS1N0/irHz21W4jt4rxzCvl
2nR42Fybap3O/g2JXMhNNROwZmNjgpsF7XVENCSuFO1jTywLaqjuXCg54IL7XVLG
omKNNNcc8h1FCeKj/nnbGMhodnFWKDTsJcbNmcOPNHo6ixzqMy/Hqc+mWYv7maAG
Jtevs3qgMZ8F9Qzr3HpUc6R3ZYYWDY/xxPisuKftOPZgtH979XC4mdf0WPnOBLqL
2DJ1zaBmjiGJolvb7XNVKcUfDXYw85ZTZQ5b9clI4e+6bmyWqQItlwt+Ati/uFEV
XzCj70B4lALX6xau1kLEpV9O1GERizYRz5P9NJNA7KoO5AVMp9w0DQTkt+LbXnZE
HHnWKy8xHQKZF9sR7YBPGLs/Ac6tviv5Ua15OgJ/8dLRZ/veyFfGo2yZsI+hKVU5
nCCJHBcAyFnm1hdvdwEdH33jDBjNB6ciotJZrf/3VYaIWSalADosHAgMWfXuWP+h
8XKXmzlxuHbTMQYtZPDgspS5aK+S4Q9wb8RRAYo=
-----END CERTIFICATE-----
"###;
        let org_name = "built-in";
        let app_name = "myapp";

        let sdk = Config::new(endpoint, client_id, client_secret, certificate, org_name, Some(app_name.to_owned())).into_sdk();
        println!("{:?}", sdk);
        println!("{:?}", sdk.authn());
    }
}
```
