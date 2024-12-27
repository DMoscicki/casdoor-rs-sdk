use serde::{Deserialize, Serialize};

use crate::{IsQueryArgs, Model};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Organization {
    owner: String,
    name: String,
    created_time: String,

    display_name: String,
    website_url: String,
    favicon: String,
    password_type: String,
    password_salt: String,
    password_options: Vec<String>,
    country_codes: Vec<String>,
    default_avatar: String,
    default_application: String,
    tags: Vec<String>,
    languages: Vec<String>,
    theme_data: Option<ThemeData>,
    master_password: String,
    init_score: i32,
    enable_soft_deletion: bool,
    is_profile_public: bool,

    mfa_items: Vec<MfaItem>,
    account_items: Vec<AccountItem>,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct AccountItem {
    name: String,
    visible: bool,
    view_rule: String,
    modify_rule: String,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct ThemeData {
    theme_type: String,
    color_primary: String,
    border_radius: i32,
    is_compact: bool,
    is_enabled: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct MfaItem {
    name: String,
    rule: String,
}

impl Model for Organization {
    fn ident() -> &'static str {
        "organization"
    }
    fn plural_ident() -> &'static str {
        "organizations"
    }
    fn support_update_columns() -> bool {
        false
    }
    fn owner(&self) -> &str {
        &self.owner
    }
    fn name(&self) -> &str {
        &self.name
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct OrganizationQueryArgs {
    #[serde(rename = "pageSize", skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub page: Option<i32>,
    #[serde(rename = "field", skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(rename = "value", skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "sortField", skip_serializing_if = "Option::is_none")]
    pub sort_field: Option<String>,
    #[serde(rename = "sortOrder", skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<String>,
    #[serde(rename = "organisationName", skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
}

impl IsQueryArgs for OrganizationQueryArgs {}
