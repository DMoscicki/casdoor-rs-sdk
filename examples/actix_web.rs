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
    // This field is not implementing in OAuth2, that is an extra field
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