use crate::domain::entities::note::NoteText;

#[derive(Debug, Clone)]
pub struct FindNote {
    pub user_id: String,
    pub note_id: String,
}

#[derive(Debug, Clone)]
pub struct UpdateNote {
    pub user_id: String,
    pub note_id: String,
    pub text: NoteText,
}

#[derive(Debug, Clone)]
pub struct FindNotes {
    pub user_id: String,
    pub page: u64,
    pub per_page: u64,
}
