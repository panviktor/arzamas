use serde_derive::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Deserialize, ToSchema)]
pub struct NoteRequestWeb {
    pub text: String,
}

#[derive(Serialize, Deserialize, IntoParams, Debug)]
pub struct NoteIdRequestWeb {
    pub id: String,
}
