mod models;
pub use models::*;

use crate::{QueryArgs, QueryResult, Sdk, SdkResult};

impl Sdk {
    pub async fn get_providers(&self, query_args: QueryArgs) -> SdkResult<QueryResult<Provider>> {
        self.get_models(None, query_args).await
    }
    pub async fn get_global_providers(&self, query_args: QueryArgs) -> SdkResult<QueryResult<Provider>> {
        let gl = String::from("global");
        self.get_models(Some(gl), query_args).await
    }
}
