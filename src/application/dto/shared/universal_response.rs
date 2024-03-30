use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
