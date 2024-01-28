use entity::prelude::Note;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// A paginated response for an entity
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema)]
#[aliases(
        ManyResponseNotes = ManyResponse<Note>
    )
]
pub struct ManyResponse<Model> {
    /// The page of data being returned
    pub data: Vec<Model>,
    /// The total number of rows available
    pub total: u64,
    /// The current page being returned
    pub current_page: u64,
    /// The number of pages available
    pub pages_count: u64,
    /// The number of rows returned in the current page
    pub per_page: u64,
}

#[derive(Deserialize, IntoParams)]
pub struct PageQuery {
    /// Page number
    pub page: u64,
    /// Number of items per page
    #[param(minimum = 1)]
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
