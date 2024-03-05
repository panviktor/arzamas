use crate::application::dto::page_query::PageQuery;
use crate::application::dto::paginated_result::PaginatedResult;
use crate::application::error::response_error::AppResponseError;
use crate::domain;
use crate::domain::note::note::NoteText;
use crate::infrastructure::persistence::db::extract_db_connection;
use crate::infrastructure::repository::error::RepositoryError;
use crate::infrastructure::repository::note::{FindNote, FindNotes, Repository, UpdateNote};
use crate::infrastructure::web::notes::dto_models::{DTOFindNote, DTONote};
use crate::modules::generate_unique_id;
use actix_web::HttpRequest;
use chrono::Utc;
use entity::note;
use entity::prelude::Note;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder,
};
use std::cmp::{max, min};

pub struct NoteService<R: Repository<domain::note::Note>> {
    note_repository: R,
}

impl<R: Repository<domain::note::Note>> NoteService<R> {
    pub fn new(note_repository: R) -> Self {
        Self { note_repository }
    }

    pub async fn create_note(
        &self,
        user_id: &str,
        note: DTONote,
    ) -> Result<domain::note::Note, RepositoryError> {
        let text = note.text.to_string();
        let id = generate_unique_id();

        let domain_note = domain::note::Note::new(
            id,
            user_id.to_string(),
            NoteText(text),
            Utc::now(),
            Utc::now(),
        );

        self.note_repository
            .create(domain_note)
            .await
            .map_err(|e| e.into())
    }

    pub async fn get_all_notes(
        &self,
        user_id: &str,
        query: PageQuery,
    ) -> Result<PaginatedResult<domain::note::Note>, RepositoryError> {
        let per_page = max(min(query.per_page, 100), 1);
        let params = FindNotes {
            user_id: user_id.to_string(),
            page: query.page,
            per_page,
        };

        let notes = self
            .note_repository
            .find_all(params)
            .await
            .map_err(RepositoryError::from)?;

        Ok(notes)
    }

    pub async fn get_note_by_id(
        &self,
        user_id: &str,
        note: DTOFindNote,
    ) -> Result<domain::note::Note, RepositoryError> {
        let note_to_repo = FindNote {
            user_id: user_id.to_string(),
            note_id: note.id,
        };

        let note = self
            .note_repository
            .find_one(note_to_repo)
            .await
            .map_err(RepositoryError::from)?;

        Ok(note)
    }

    pub async fn delete_note(
        &self,
        user_id: &str,
        note: DTOFindNote,
    ) -> Result<(), RepositoryError> {
        let note_to_repo = FindNote {
            user_id: user_id.to_string(),
            note_id: note.id,
        };

        self.note_repository
            .delete(note_to_repo)
            .await
            .map_err(RepositoryError::from)?;

        Ok(())
    }

    pub async fn update_note(
        &self,
        user_id: &str,
        note_id: &str,
        note: DTONote,
    ) -> Result<domain::note::Note, RepositoryError> {
        let updated_note = UpdateNote {
            user_id: user_id.to_string(),
            note_id: note_id.to_string(),
            text: NoteText(note.text),
        };

        self.note_repository
            .update(updated_note)
            .await
            .map_err(RepositoryError::from)
    }
}
