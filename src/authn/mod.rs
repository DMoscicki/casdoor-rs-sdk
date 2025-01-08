mod models;

use crate::{Method, QueryArgs, QueryResult, Sdk, SdkError, SdkResult, NO_BODY};
use anyhow::Result;
use jsonwebtoken::{
    errors::{Error, ErrorKind},
    Algorithm, DecodingKey, TokenData, Validation,
};
pub use models::*;
use oauth2::{AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, IntrospectionUrl, RedirectUrl, RefreshToken, TokenUrl};
use openssl::{
    base64,
    pkey::{PKey, Public},
    sha::sha256,
};
use rand::Rng;
use std::{fmt::Write, iter};
pub use oauth2::{basic::BasicTokenIntrospectionResponse, TokenIntrospectionResponse};
use oauth2::url;
use uuid::Uuid;

impl Sdk {
    pub fn authn(&self) -> AuthSdk {
        AuthSdk { sdk: self.clone() }
    }
}

#[derive(Debug, Clone)]
pub struct AuthSdk {
    sdk: Sdk,
}

impl AuthSdk {
    fn client_id(&self) -> ClientId {
        ClientId::new(self.sdk.client_id.to_string())
    }

    fn client_secret(&self) -> ClientSecret {
        ClientSecret::new(self.sdk.client_secret.to_string())
    }

    fn auth_url(&self, url_path: &str) -> Result<AuthUrl, url::ParseError> {
        let mut url = String::new();

        url.write_str(&self.sdk.endpoint).unwrap();
        url.write_str(url_path).unwrap();

        AuthUrl::new(url)
    }

    fn token_url(&self, url_path: &str) -> Result<TokenUrl, url::ParseError> {
        let mut url = String::new();

        url.write_str(&self.sdk.endpoint).unwrap();
        url.write_str(url_path).unwrap();

        Ok(TokenUrl::new(url)?)
    }

    fn introspect_url(&self, url_path: &str) -> Result<IntrospectionUrl> {
        let mut url = String::new();

        url.write_str(&self.sdk.endpoint)?;
        url.write_str(url_path)?;

        Ok(IntrospectionUrl::new(url)?)
    }

    fn logout_url(&self, path: String) -> String {
        let mut logout_url = String::new();

        logout_url.write_str(&self.sdk.endpoint).unwrap();
        logout_url.write_str(&path).unwrap();

        logout_url
    }

    /// Gets the pivotal and necessary secret to interact with the Casdoor server
    pub async fn get_oauth_token(&self, code: String) -> SdkResult<CasdoorTokenResponse> {
        let casdoor_client = OAuth2Client::new(self.client_id(), self.client_secret(), self.auth_url("/api/login/oauth/authorize")?)
            .await
            .unwrap();

        let token_res: CasdoorTokenResponse = casdoor_client
            .get_oauth_token(
                AuthorizationCode::new(code),
                RedirectUrl::new(self.sdk.endpoint.to_string())?,
                self.token_url("/api/login/oauth/access_token")?,
            )
            .await
            .unwrap();

        Ok(token_res)
    }

    /// Refreshes the OAuth token
    pub async fn refresh_oauth_token(&self, refresh_token: String) -> SdkResult<CasdoorTokenResponse> {
        let casdoor_client = OAuth2Client::new(self.client_id(), self.client_secret(), self.auth_url("/api/login/oauth/authorize")?)
            .await
            .unwrap();

        let token_res = casdoor_client
            .refresh_token(RefreshToken::new(refresh_token), self.token_url("/api/login/oauth/refresh_token")?)
            .await
            .unwrap();

        Ok(token_res)
    }

    pub async fn introspect_access_token(&self, token: String) -> SdkResult<BasicTokenIntrospectionResponse> {
        let client = OAuth2Client::new(self.client_id(), self.client_secret(), self.auth_url("/api/login/oauth/authorize")?)
            .await
            .unwrap();

        let tk: AccessToken = AccessToken::new(token);

        let intro_res = client
            .get_introspect_access_token(self.introspect_url("/api/login/oauth/introspect").unwrap(), &tk)
            .await
            .unwrap();

        Ok(intro_res)
    }

    pub fn parse_jwt_token(&self, token: &str) -> SdkResult<Claims> {
        let header = jsonwebtoken::decode_header(token)?;

        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[&self.sdk.client_id]);
        validation.validate_aud = true;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let pb_key = self.sdk.replace_cert_to_pub_key().unwrap();

        // TODO: Add ES512 support after https://github.com/Keats/jsonwebtoken/issues/250#issuecomment-2488307814
        match header.alg {
            Algorithm::ES256 => {
                let token_data: TokenData<Claims> = get_tk_es(pb_key, validation, token);

                Ok(token_data.claims)
            }
            Algorithm::ES384 => {
                let token_data: TokenData<Claims> = get_tk_es(pb_key, validation, token);

                Ok(token_data.claims)
            }
            Algorithm::RS256 => {
                let token_data: TokenData<Claims> = get_tk_rsa(pb_key, validation, token);

                Ok(token_data.claims)
            }
            Algorithm::RS512 => {
                let token_data: TokenData<Claims> = get_tk_rsa(pb_key, validation, token);

                Ok(token_data.claims)
            }
            _ => Err(SdkError::from(Error::from(ErrorKind::InvalidAlgorithm))),
        }
    }

    pub fn get_signing_url(&self, redirect_url: String) -> String {
        let scope = "read";
        let state = self.sdk.app_name.clone().unwrap_or_default();
        let base = format!("{}/login/oauth/authorize", self.sdk.endpoint);
        let nonce = Uuid::new_v4();

        let signing_url = url::Url::parse_with_params(
            base.as_str(),
            &[
                ("client_id", self.client_id().as_str()),
                ("redirect_uri", redirect_url.as_str()),
                ("scope", scope),
                ("response_type", "code"),
                ("state", state.as_str()),
                ("code_challenge_method", "S256"),
                ("nonce", nonce.to_string().as_str()),
                ("code_challenge", generate_code_challange(generate_random_string(43)).as_str()),
            ],
        )
        .unwrap();

        signing_url.to_string()
    }

    pub async fn logout(&self, id_token: &str, post_logout_redirect_uri: &str, state: &str) -> SdkResult<String> {
        let logout_url = url::Url::parse_with_params(
            self.logout_url("/api/logout".to_string()).as_str(),
            &[
                ("id_token_hint", id_token),
                ("post_logout_redirect_uri", post_logout_redirect_uri),
                ("state", state),
            ],
        )?;

        let client = reqwest::Client::new();

        let response = client.post(logout_url).send().await?.text().await?;

        Ok(response)
    }

    pub fn get_signup_url(&self, redirect_url: String) -> String {
        redirect_url.replace("/login/oauth/authorize", "/signup/oauth/authorize")
    }

    pub fn get_signup_url_enable_password(&self) -> String {
        format!("{}/signup/{}", self.sdk.endpoint, self.sdk.app_name.clone().unwrap_or_default())
    }

    pub fn get_user_profile_url(&self, uname: String, token: Option<String>) -> String {
        let param = match token {
            Some(token) if !token.is_empty() => format!("?access_token={}", token),
            _ => "".to_string(),
        };
        format!("{}/users/{}/{uname}{param}", self.sdk.endpoint, self.sdk.org_name)
    }

    pub fn get_my_profile_url(&self, token: Option<String>) -> String {
        let param = match token {
            Some(token) if !token.is_empty() => format!("?access_token={}", token),
            _ => "".to_string(),
        };
        format!("{}/account{}", self.sdk.endpoint, param)
    }

    pub async fn get_sessions(&self, query_args: QueryArgs) -> SdkResult<QueryResult<Session>> {
        self.sdk.get_models(None, query_args).await
    }

    pub async fn get_session(&self, session_pk_id: &str) -> SdkResult<Session> {
        self.sdk
            .request_data(
                Method::GET,
                self.sdk.get_url_path("get-session", true, [("sessionPkId", session_pk_id)])?,
                NO_BODY,
            )
            .await?
            .into_data_default()
    }

    pub async fn is_session_duplicated(&self, session_pk_id: &str, session_id: &str) -> SdkResult<bool> {
        self.sdk
            .request_data(
                Method::GET,
                self.sdk
                    .get_url_path("is-session-duplicated", true, [("sessionPkId", session_pk_id), ("sessionId", session_id)])?,
                NO_BODY,
            )
            .await?
            .into_data_default()
    }
}

fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
    let mut rng = rand::thread_rng();
    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    iter::repeat_with(one_char).take(length).collect()
}

fn generate_code_challange(verifier: String) -> String {
    let bb = verifier.as_bytes();
    let digest = sha256(bb);
    base64::encode_block(&digest).replace("=", "-")
}

fn get_tk_es(pb_key: PKey<Public>, validation: Validation, token: &str) -> TokenData<Claims> {
    let public_key = pb_key.ec_key().unwrap().public_key_to_pem().unwrap();
    let decode_key = &DecodingKey::from_ec_pem(&public_key).unwrap();
    let token_data: TokenData<Claims> = jsonwebtoken::decode(token, decode_key, &validation).unwrap();

    token_data
}

fn get_tk_rsa(pb_key: PKey<Public>, validation: Validation, token: &str) -> TokenData<Claims> {
    let public_key = pb_key.rsa().unwrap().public_key_to_pem().unwrap();
    let decode_key = &DecodingKey::from_rsa_pem(&public_key).unwrap();
    let td: TokenData<Claims> = jsonwebtoken::decode(token, decode_key, &validation).unwrap();

    td
}
#[cfg(test)]
mod tests {
    use std::fs;

    use crate::Config;

    #[test]
    fn successfully_es256() {
        let token = fs::read_to_string("./src/authn/testdata/tok_es256.txt").unwrap();
        let cert = fs::read_to_string("./src/authn/testdata/cert_es256.txt").unwrap();
        let cfg = Config::new(
            "http://localhost:8000".to_string(),
            "7883231e5f0792b5acdf".to_string(),
            "secret".to_string(),
            cert,
            "org_name".to_string(),
            Some("app_name".to_owned())
        )
        .into_sdk();

        let authnx = cfg.authn();

        let tk = authnx.parse_jwt_token(&token).unwrap();
        assert_eq!("user1", tk.user.display_name);
    }

    #[test]
    fn successfully_es384() {
        let token = fs::read_to_string("./src/authn/testdata/tok_es384.txt").unwrap();
        let cert = fs::read_to_string("./src/authn/testdata/cert_es384.txt").unwrap();
        let cfg = Config::new(
            "http://localhost:8000".to_string(),
            "7883231e5f0792b5acdf".to_string(),
            "secret".to_string(),
            cert,
            "org_name".to_string(),
            Some("app_name".to_owned())
        )
        .into_sdk();

        let authnx = cfg.authn();

        let tk = authnx.parse_jwt_token(&token).unwrap();
        assert_eq!("user1", tk.user.display_name);
    }

    #[test]
    fn successfully_rs512() {
        let token = fs::read_to_string("./src/authn/testdata/tok_rs512.txt").unwrap();
        let cert = fs::read_to_string("./src/authn/testdata/cert_rs256.txt").unwrap();
        let cfg = Config::new(
            "http://localhost:8000".to_string(),
            "7883231e5f0792b5acdf".to_string(),
            "secret".to_string(),
            cert,
            "org_name".to_string(),
            Some("app_name".to_owned())
        )
        .into_sdk();

        let authnx = cfg.authn();

        let tk = authnx.parse_jwt_token(&token).unwrap();
        assert_eq!("user1", tk.user.display_name);
    }

    #[test]
    #[should_panic]
    fn bad_algo_rs_tk256_cert512() {
        let token = fs::read_to_string("./src/authn/testdata/tok_rs256.txt").unwrap();
        let cert = fs::read_to_string("./src/authn/testdata/cert_rs512.txt").unwrap();
        let cfg = Config::new(
            "http://localhost:8000".to_string(),
            "e953686f04e7055b698b".to_string(),
            "secret".to_string(),
            cert,
            "org_name".to_string(),
            Some("app_name".to_owned())
        )
        .into_sdk();

        let authnx = cfg.authn();

        let _tk = authnx.parse_jwt_token(&token).unwrap();
    }

    #[test]
    #[should_panic]
    fn bad_algo_es_tk256_cert512() {
        let token = fs::read_to_string("./src/authn/testdata/tok_es256.txt").unwrap();
        let cert = fs::read_to_string("./src/authn/testdata/cert_es384.txt").unwrap();
        let cfg = Config::new(
            "http://localhost:8000".to_string(),
            "e953686f04e7055b698b".to_string(),
            "secret".to_string(),
            cert,
            "org_name".to_string(),
            Some("app_name".to_owned())
        )
        .into_sdk();

        let authnx = cfg.authn();

        let _tk = authnx.parse_jwt_token(&token).unwrap();
    }
}
