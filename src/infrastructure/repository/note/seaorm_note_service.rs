use crate::domain::note::note::{Note, NoteText};
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

impl Note {
    fn try_from_active_sea_model(active_model: note::ActiveModel) -> Result<Self, Error> {
        let note_id = match active_model.note_id {
            Set(value) => Ok(value),
            _ => Err("note_id is missing".to_string()),
        }?;

        let user_id = match active_model.user_id {
            Set(value) => Ok(value),
            _ => Err("user_id is missing".to_string()),
        }?;

        let text_str = match active_model.text {
            Set(value) => Ok(value),
            _ => Err("text is missing".to_string()),
        }?;
        let text = NoteText::try_from(text_str).map_err(|_| "Invalid note text".to_string())?;

        let created_at_naive = match active_model.created_at {
            Set(value) => Ok(value),
            _ => Err("created_at is missing".to_string()),
        }?;

        let updated_at_naive = match active_model.updated_at {
            Set(value) => Ok(value),
            _ => Err("updated_at is missing".to_string()),
        }?;

        let created_at = Utc.from_utc_datetime(&created_at_naive);
        let updated_at = Utc.from_utc_datetime(&updated_at_naive);

        Ok(Note::new(note_id, user_id, text, created_at, updated_at))
    }

    fn try_from_sea_model(model: note::Model) -> Result<Self, Error> {
        let note_id = model.note_id;
        let user_id = model.user_id;
        let text = NoteText::try_from(model.text).map_err(|_| "Invalid note text".to_string())?;
        let created_at = Utc.from_utc_datetime(&model.created_at);
        let updated_at = Utc.from_utc_datetime(&model.updated_at);

        Ok(Note::new(note_id, user_id, text, created_at, updated_at))
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
