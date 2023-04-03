use serde::{Deserialize, Serialize};

/// A paginated response for an entity
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
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

#[derive(Deserialize)]
pub struct PageQuery {
    pub page: u64,
    pub per_page: u64,
}
