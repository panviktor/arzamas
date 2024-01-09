use serde_derive::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, ToSchema)]
pub struct DTONote {
    pub(crate) text: String,
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct FindNote {
    pub(crate) id: String,
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateNote {
    pub(crate) id: String,
    pub(crate) text: String,
}
