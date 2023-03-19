use actix_http::{ StatusCode };
use actix_web::{ HttpRequest };
use chrono::Utc;
use sea_orm::{
    ActiveValue::Set,
    ActiveModelTrait,
    EntityTrait,
    PaginatorTrait,
    QueryOrder,
    QueryFilter,
    ColumnTrait,
    ModelTrait,
};
use serde::{Deserialize, Serialize};
use entity::{note, user};
use entity::prelude::Note;

use crate::core::db::DB;
use crate::models::ServiceError;
use crate::models::many_response::{ ManyResponse, PageQuery};
use crate::modules::generate_unique_id;

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct DTONote {
    pub(crate) text: String,
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct FindNote {
    pub(crate) id: String,
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct CreateNote {
    pub(crate) id: String,
    pub(crate) text: String,
}

pub async fn try_create_note (
    req: HttpRequest,
    user_id: &str,
    params: DTONote
) -> Result<(), ServiceError> {

    let db = &*DB;
    let text =  params.text.to_string();
    let id = generate_unique_id();

    let user = note::ActiveModel {
        user_id: Set(user_id.to_string()),
        note_id: Set(id),
        text: Set(text),
        created_at: Set( Utc::now().naive_utc()),
        updated_at: Set( Utc::now().naive_utc()),
        ..Default::default()
    };

    match user.insert(db).await {
        Ok(_) => { Ok(()) }
        Err(err) => {
            Err(ServiceError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: req.path().to_string(),
                message: err.to_string(),
                show_message: true,
            })
        }
    }
}

pub async fn try_get_all_notes(
    req: HttpRequest,
    user_id: &str,
    info: PageQuery,
) -> Result<ManyResponse<note::Model>, ServiceError> {
    let db = &*DB;
    let to_find = user_id.to_string();
    let user= entity::prelude::User::find()
        .filter(user::Column::UserId.eq(to_find))
        .one(db)
        .await
        .map_err(|e| ServiceError {
            code: StatusCode::NOT_FOUND,
            path: "BD".to_string(),
            message: e.to_string(),
            show_message: true,
        });

    if let Ok(user) = user {
        if let Some(user) = user {
            // Set page number and items per page
            let page = info.page;
            let per_page = info.per_page;

            let paginator = user
                .find_related(Note)
                .paginate(db, per_page);

            let num_items_and_pages = paginator.num_items_and_pages().await?;
            let number_of_pages= num_items_and_pages.number_of_pages;
            let total= num_items_and_pages.number_of_items;

            let page = page.max(1);
            let data: Vec<note::Model> = paginator
                .fetch_page(page - 1)
                .await
                .map_err(|e| ServiceError::general(&req, e.to_string(), true))?;

            let result = ManyResponse {
                data,
                total,
                current_page: page,
                pages_count: number_of_pages,
                per_page,
            };
            return Ok(result)
        }
    }

    Err(
        ServiceError::not_found(
            &req,
            "Notes not found".to_string(),
            false
        )
    )
}

pub async fn try_get_by_id_notes(
    req: HttpRequest,
    user_id: &str,
    params: FindNote
) -> Result<note::Model, ServiceError> {
    let db = &*DB;

    if let Some(note) = Note::find()
        .filter(note::Column::NoteId.contains(&*params.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await? {
        if note.user_id == user_id {
            return Ok(note)
        }
    }

    Err(
        ServiceError::not_found(
            &req,
            "Note not found".to_string(),
            false
        )
    )
}

pub async fn try_delete_note(
    req: HttpRequest,
    user_id: &str,
    params: FindNote
) ->  Result<(), ServiceError> {
    let db = &*DB;

    if let Some(note) = Note::find()
        .filter(note::Column::NoteId.contains(&*params.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await? {
            if note.user_id == user_id {
                note.delete(db).await?;
                return Ok(());
            }
    }
    Err(
        ServiceError::not_found(
            &req,
            "Note not found".to_string(),
            false
        )
    )
}

pub async fn try_update_note(
    req: HttpRequest,
    user_id: &str,
    params: CreateNote
) ->  Result<(), ServiceError> {

    let db = &*DB;
    let new_text = params.text.to_string();

    if let Some(note) = Note::find()
        .filter(note::Column::NoteId.contains(&*params.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await? {
        if note.user_id == user_id {
            let mut active: note::ActiveModel = note.into();
            active.text = Set(new_text.to_owned());
            active.updated_at = Set( Utc::now().naive_utc());
            active.update(db).await?;
            return Ok(())
        }
    }

    Err(
        ServiceError::not_found(
            &req,
            "Note not found".to_string(),
            false
        )
    )
}