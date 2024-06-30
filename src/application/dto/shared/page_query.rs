use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
pub struct PageQuery {
    /// Page number
    pub page: u64,
    /// Number of items per page
    #[param(maximum = 100, minimum = 1)]
    pub per_page: u64,
}
