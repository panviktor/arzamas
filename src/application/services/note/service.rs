use crate::application::dto::many_response::PageQuery;
use crate::application::dto::paginated_result::PaginatedResult;
use crate::application::error::response_error::AppResponseError;
use crate::domain;
use crate::domain::note::note::NoteText;
use crate::infrastructure::persistence::db::extract_db_connection;
use crate::infrastructure::repository::error::RepositoryError;
use crate::infrastructure::repository::note::{FindNotes, Repository};
use crate::infrastructure::web::notes::dto_models::{DTONote, FindNote};
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
}

pub async fn try_get_by_id_notes(
    req: &HttpRequest,
    user_id: &str,
    note: FindNote,
) -> Result<note::Model, AppResponseError> {
    let db = extract_db_connection(req)?;

    if let Some(note) = Note::find()
        .filter(note::Column::NoteId.contains(note.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await?
    {
        if note.user_id == user_id {
            return Ok(note);
        }
    }

    Err(AppResponseError::not_found(
        &req,
        "Note not found".to_string(),
        false,
    ))
}

pub async fn try_delete_note(
    req: &HttpRequest,
    user_id: &str,
    params: FindNote,
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;

    if let Some(note) = Note::find()
        .filter(note::Column::NoteId.contains(params.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await?
    {
        if note.user_id == user_id {
            note.delete(db).await?;
            return Ok(());
        }
    }
    Err(AppResponseError::not_found(
        &req,
        "Note not found".to_string(),
        false,
    ))
}

pub async fn try_update_note(
    req: &HttpRequest,
    user_id: &str,
    note_id: &str,
    body: DTONote,
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;

    let new_text = body.text.to_string();

    if let Some(note) = Note::find()
        .filter(note::Column::NoteId.contains(note_id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await?
    {
        if note.user_id == user_id {
            let mut active: note::ActiveModel = note.into();
            active.text = Set(new_text.to_owned());
            active.updated_at = Set(Utc::now().naive_utc());
            active.update(db).await?;
            return Ok(());
        }
    }

    Err(AppResponseError::not_found(
        &req,
        "Note not found".to_string(),
        false,
    ))
}
