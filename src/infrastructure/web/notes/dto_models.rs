use serde_derive::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct DTONote {
    pub(crate) text: String,
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, IntoParams, Debug)]
pub(crate) struct FindNote {
    pub(crate) id: String,
}
