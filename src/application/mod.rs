mod models;
pub use models::*;

use crate::{Method, QueryResult, Sdk, SdkResult, NO_BODY};

impl Sdk {
    pub async fn get_user_application(&self, user_name: &str) -> SdkResult<Option<Application>> {
        self.request_data(Method::GET, format!("/api/get-user-application?id={}", self.id(user_name)), NO_BODY)
            .await?
            .into_data()
    }

    pub async fn get_applications(&self, query_args: ApplicationQueryArgs) -> SdkResult<QueryResult<Application>> {
        self.get_models(None, query_args).await
    }

    pub async fn get_organization_applications(&self, query_args: ApplicationQueryArgs) -> SdkResult<QueryResult<Application>> {
        let org = String::from("organization");
        self.get_models(Some(org), query_args).await
    }
}
