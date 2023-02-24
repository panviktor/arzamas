use serde::{Deserialize, Serialize};

/// A paginated response for an entity
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ManyResponse<Model> {
    /// The page of data being returned
    pub data: Vec<Model>,
    /// The number of rows returned in the current page
    pub count: u64,
    /// The total number of rows available
    pub total: u64,
    /// The current page being returned
    pub page: u64,
    /// The number of pages available
    pub page_count: u64,
}