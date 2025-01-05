use std::time::Duration;

use crate::{Model, User};
use anyhow::{Ok, Result};
pub use oauth2::TokenResponse;
use oauth2::{
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse, BasicTokenType},
    AccessToken, AuthType, AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, EndpointNotSet, EndpointSet, ExtraTokenFields,
    IntrospectionUrl, RedirectUrl, RefreshToken, Scope, StandardRevocableToken, StandardTokenResponse, TokenUrl,
};
use reqwest::{redirect, ClientBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Claims {
    #[serde(flatten)]
    pub user: User,
    pub access_token: String,
    pub tag: String,
    pub token_type: Option<String>,
    pub nonce: Option<String>,
    pub scope: Option<String>,
    // #[serde(flatten)]
    // pub reg_claims: RegisteredClaims,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Session {
    owner: String,
    name: String,
    application: String,
    created_time: String,
    session_id: Vec<String>,
}

impl Session {
    pub fn get_pk_id(&self) -> String {
        format!("{}/{}/{}", self.owner, self.name, self.application)
    }
}

impl Model for Session {
    fn ident() -> &'static str {
        "session"
    }
    fn plural_ident() -> &'static str {
        "sessions"
    }
    fn support_update_columns() -> bool {
        true
    }
    fn owner(&self) -> &str {
        &self.owner
    }
    fn name(&self) -> &str {
        &self.name
    }
}

impl ExtraTokenFields for CasdoorExtraTokenFields {}

#[derive(Debug, Deserialize, Serialize)]
pub struct CasdoorExtraTokenFields {
    // This field only use in OpenID Connect
    pub id_token: String,
}

pub type CasdoorTokenResponse = StandardTokenResponse<CasdoorExtraTokenFields, BasicTokenType>;

pub type CasdoorClient<
    HasAuthUrl = EndpointSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = Client<
    BasicErrorResponse,
    CasdoorTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CasdoorResponse<EF: ExtraTokenFields> {
    pub access_token: AccessToken,
    pub token_type: BasicTokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "oauth2::helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "oauth2::helpers::serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub scopes: Option<Vec<Scope>>,

    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    pub extra_fields: EF,
}

impl<EF> TokenResponse for CasdoorResponse<EF>
where
    EF: ExtraTokenFields,
{
    type TokenType = BasicTokenType;
    /// REQUIRED. The access token issued by the authorization server.
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    /// But in this particular case as the service is non compliant, it has a default value
    fn token_type(&self) -> &BasicTokenType {
        &self.token_type
    }
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scope of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

pub struct OAuth2Client {
    pub client: CasdoorClient,
    pub http_client: reqwest::Client,
}

impl OAuth2Client {
    pub(crate) async fn new(client_id: ClientId, client_secret: ClientSecret, auth_url: AuthUrl) -> Result<Self> {
        let http_client = ClientBuilder::new()
            .redirect(redirect::Policy::default())
            .build()
            .expect("Client must build");

        let client = CasdoorClient::new(client_id)
            .set_client_secret(client_secret)
            .set_auth_uri(auth_url)
            .set_auth_type(AuthType::RequestBody);

        Ok(Self { client, http_client })
    }

    pub async fn refresh_token(self, refresh_token: RefreshToken, token_url: TokenUrl)
        -> Result<CasdoorTokenResponse> {
        let token_res: CasdoorTokenResponse = self
            .client
            .set_token_uri(token_url)
            .exchange_refresh_token(&refresh_token)
            .add_scope(Scope::new("read".to_string()))
            .request_async(&self.http_client)
            .await?;

        Ok(token_res)
    }

    pub async fn get_oauth_token(self, code: AuthorizationCode, redirect_url: RedirectUrl, token_url: TokenUrl)
        -> Result<CasdoorTokenResponse> {
        let token_res = self
            .client
            .set_redirect_uri(redirect_url)
            .set_token_uri(token_url)
            .exchange_code(code)
            .request_async(&self.http_client)
            .await?;

        Ok(token_res)
    }

    pub async fn get_introspect_access_token(self, intro_url: IntrospectionUrl, token: &AccessToken)
        -> Result<BasicTokenIntrospectionResponse> {
        let res = self
            .client
            .set_introspection_url(intro_url)
            .introspect(token)
            .request_async(&self.http_client)
            .await?;

        Ok(res)
    }
}
