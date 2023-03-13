use actix_http::{ StatusCode };
use actix_web::{HttpRequest, HttpResponse, web};
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
    DeleteResult
};
use serde::{Deserialize, Serialize};
use entity::{note, user};
use entity::prelude::Note;
use crate::core::db::DB;
use crate::models::ServiceError;
use crate::models::many_response::{ ManyResponse, PageQuery};
use crate::modules::auth::middleware::LoginUser;
use crate::modules::generate_unique_id;

pub async fn create_note(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<DTONote>
) -> Result<HttpResponse, ServiceError> {

    let db = &*DB;
    let text =  params.text.to_string();
    let id = generate_unique_id();

    let user = note::ActiveModel {
        user_id: Set(user.id.to_string()),
        note_id: Set(id),
        text: Set(text),
        created_at: Set( Utc::now().naive_utc()),
        updated_at: Set( Utc::now().naive_utc()),
        ..Default::default()
    };

    let result = user.insert(db).await;
    match result {
        Ok(_) => { Ok(HttpResponse::Ok().finish()) }
        Err(err) => {
            Err(ServiceError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: req.path().to_string(),
                message: err.to_string(),
                show_message: false,
            })
        }
    }
}

pub async fn get_all_notes(
    req: HttpRequest,
    info: web::Query<PageQuery>,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {

    let db = &*DB;
    let to_find = user.id.to_string();
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
                match user {
                    Some(user) => {
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

                        return Ok(HttpResponse::Ok().json(result))

                    }
                    None => {}
                }
        }

    Err(ServiceError {
        code: StatusCode::NOT_FOUND,
        path: "BD".to_string(),
        message: "Notes not found".to_string(),
        show_message: true,
    })
}

pub async fn get_by_id(
    user: LoginUser,
    params: web::Json<FindNote>
) -> Result<HttpResponse, ServiceError> {

    let db = &*DB;

    let note: Option<note::Model> = Note::find()
        .filter(note::Column::NoteId.contains(&*params.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await?;

    if let Some(note) = note {
       if note.user_id == user.id {
           return Ok(HttpResponse::Ok().json(note));
       }
    }

    Err(ServiceError {
        code: StatusCode::NOT_FOUND,
        path: "BD".to_string(),
        message: "Note not found".to_string(),
        show_message: true,
    })
}

pub async fn delete(
    user: LoginUser,
    params: web::Json<FindNote>
) -> Result<HttpResponse, ServiceError> {

    let db = &*DB;

    let note: Option<note::Model> = Note::find()
        .filter(note::Column::NoteId.contains(&*params.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await?;

    if let Some(note) = note {
        if note.user_id == user.id {
            let res: DeleteResult = note.delete(db).await?;
            return Ok(HttpResponse::Ok().json(res.rows_affected));
        }
    }

    Err(ServiceError {
        code: StatusCode::NOT_FOUND,
        path: "BD".to_string(),
        message: "Note not found".to_string(),
        show_message: true,
    })
}

pub async fn update(
    user: LoginUser,
    params: web::Json<CreateNote>
) -> Result<HttpResponse, ServiceError> {

    let db = &*DB;
    let new_text = params.text.to_string();

    let note: Option<note::Model> = Note::find()
        .filter(note::Column::NoteId.contains(&*params.id.to_string()))
        .order_by_asc(note::Column::Id)
        .one(db)
        .await?;

    if let Some(note) = note {
        if note.user_id == user.id {
            let mut active: note::ActiveModel = note.into();
            active.text = Set(new_text.to_owned());
            active.updated_at = Set( Utc::now().naive_utc());
            active.update(db).await?;
            return Ok(HttpResponse::Ok().json("Note updated"));
        }
    }

    Err(ServiceError {
        code: StatusCode::NOT_FOUND,
        path: "BD".to_string(),
        message: "Notes not found".to_string(),
        show_message: true,
    })
}

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