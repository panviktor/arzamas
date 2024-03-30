use serde_derive::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateNoteRequest {
    pub user_id: String,
    pub text: String,
}
impl CreateNoteRequest {
    pub fn new(user_id: &str, text: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            text: text.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, IntoParams, Debug)]
pub struct UpdateNoteRequest {
    pub user_id: String,
    pub note_id: String,
    pub text: String,
}

impl UpdateNoteRequest {
    pub fn new(user_id: &str, note_id: &str, text: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            note_id: note_id.to_string(),
            text: text.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAllNotesRequest {
    pub user_id: String,
    pub page: u64,
    pub per_page: u64,
}

impl GetAllNotesRequest {
    pub fn new(user_id: &str, page: u64, per_page: u64) -> Self {
        Self {
            user_id: user_id.to_string(),
            page,
            per_page,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NoteByIdRequest {
    pub user_id: String,
    pub note_id: String,
}

impl NoteByIdRequest {
    pub fn new(user_id: &str, note_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            note_id: note_id.to_string(),
        }
    }
}
