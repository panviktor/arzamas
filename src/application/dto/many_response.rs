use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, IntoParams)]
pub struct PageQuery {
    /// Page number
    pub page: u64,
    /// Number of items per page
    #[param(maximum = 100, minimum = 1)]
    pub per_page: u64,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UniversalResponse {
    pub title: String,
    pub description: Option<String>,
    pub show_to_user: bool,
}

impl UniversalResponse {
    pub fn new(title: String, description: Option<String>, show_to_user: bool) -> Self {
        UniversalResponse {
            title,
            description,
            show_to_user,
        }
    }
}
