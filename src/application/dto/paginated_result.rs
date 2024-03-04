use entity::prelude::Note;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema)]
#[aliases(
PaginatedResultNotes = PaginatedResult < Note >
)
]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total_items: u64,
    pub total_pages: u64,
    pub current_page: u64,
    pub items_per_page: u64,
}