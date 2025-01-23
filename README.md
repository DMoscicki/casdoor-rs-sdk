### Features:
* Add openssl for parsing certificate and getting Public Key from it;
* Delete `cubix` and `salvo` dependencies;
* Delete getters;
* Support decoding multiple jsonwebtoken algos;
* Add JWT validation;
* Write Casdoor OAuth2 client for getting access_token;

This lib use latest [OAuth2 Release](https://github.com/ramosbugs/oauth2-rs/tree/5.0.0) with big API update.
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

## Example init Casdoor config

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

## Example with `actix_web_httpauth` and `actix_web`

```rust
use actix_web::{error, post, HttpResponse, web::{Bytes, Data}, dev::ServiceRequest, HttpServer, App};
use actix_web_httpauth::{middleware::HttpAuthentication, extractors::bearer::BearerAuth};
use casdoor_sdk_rust::{AuthSdk, BasicTokenType, Config};
use oauth2::{TokenIntrospectionResponse, TokenResponse};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct NewToken {
    access_token: String,
    token_type: BasicTokenType,
    expires_in: Option<u64>,
    refresh_token: String,
    scopes: String,
    // This field is not implementing in OAuth2, thats it's an extra field
    // and its only use in OpenID Connect
    id_token: String
}

async fn validation(
    req: ServiceRequest,
    credentials: Option<BearerAuth>
) -> Result<ServiceRequest, (error::Error, ServiceRequest)> {
    match credentials {
        Some(token) => {
            let auth_sdk = req.app_data::<Data<AuthSdk>>().unwrap();

            let bearer_token = auth_sdk.parse_jwt_token(token.token());

            match bearer_token {
                Ok(tk) => {
                    println!("request from: {:?}", tk.user);
                    // https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
                    // if token is not active it's not valid
                    let flag = auth_sdk.introspect_access_token(token.token().to_string()).await.unwrap();

                    if flag.active() {
                        Ok(req)
                    } else {
                        Err((error::ErrorUnauthorized("token must be active, refresh it"), req))
                    }
                }
                Err(e) => {
                    Err((error::ErrorUnauthorized(format!("bad bearer: {}", e.to_string())), req))
                }
            }
        },
        None => {
            Err((error::ErrorBadRequest("request is not valid"), req))
        }
    }
}

#[post("/refresh_token")]
pub async fn refresh_token(bytes: Bytes, csd: Data<AuthSdk>) -> HttpResponse {
    match String::from_utf8(bytes.to_vec()) {
        Ok(token_string) => {
            let tk = csd.refresh_oauth_token(token_string).await.unwrap();
            let tk_struct = NewToken{
                access_token: tk.access_token().secret().to_owned(),
                token_type: tk.token_type().to_owned(),
                expires_in: Some(tk.expires_in().unwrap().as_secs()),
                refresh_token: tk.refresh_token().unwrap().secret().to_owned(),
                scopes: tk.scopes().unwrap()[0].to_string(),
                id_token: tk.extra_fields().id_token.to_string(),
            };

            let tk_answer_json = serde_json::to_string(&tk_struct).unwrap();
            HttpResponse::Ok().body(tk_answer_json)
        }
        Err(e) => {
            HttpResponse::BadRequest().body(e.to_string())
        }
    }
}

fn init_casdoor() -> AuthSdk {
    let app = Config::from_toml("./casdoor.toml").unwrap();
    app.into_sdk().authn()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || {
        let auth = HttpAuthentication::with_fn(validation);
        let auth_sdk = init_casdoor();

        App::new()
            .service(refresh_token)
            .app_data(auth_sdk)
            .wrap(auth)
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
```