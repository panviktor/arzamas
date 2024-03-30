use crate::domain::entities::note::{Note, NoteText};
use chrono::{TimeZone, Utc};
use entity::note;
use sea_orm::ActiveValue::Set;

type Error = String;
impl Note {
    // Add a method to convert `Note` into `note::ActiveModel`
    pub fn into_active_model(self) -> note::ActiveModel {
        note::ActiveModel {
            note_id: Set(self.note_id),
            user_id: Set(self.user_id),
            text: Set(self.text.value().clone()),
            created_at: Set(self.created_at.naive_utc()),
            updated_at: Set(self.updated_at.naive_utc()),
            ..Default::default()
        }
    }
}

impl From<note::Model> for Note {
    fn from(model: note::Model) -> Self {
        let text = NoteText::try_from(model.text).expect("Invalid note text");

        Note {
            note_id: model.note_id,
            user_id: model.user_id,
            text,
            created_at: Utc.from_utc_datetime(&model.created_at),
            updated_at: Utc.from_utc_datetime(&model.updated_at),
        }
    }
}
