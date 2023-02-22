use actix_http::{ StatusCode };
use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, ModelTrait};
use sea_orm::ActiveValue::Set;
use sea_orm::QueryFilter;
use sea_orm::ColumnTrait;
use serde::{Deserialize, Serialize};
use entity::{note, user};
use entity::prelude::Note;
use crate::core::db::DB;
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;

pub async fn create_note(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<DTONote>
) -> Result<HttpResponse, ServiceError> {
    println!("i get struct, {:?}", user.id);
    // insert note
    let db = &*DB;
    let text =  params.text.to_string();

    let user = note::ActiveModel {
        user_id: Set(user.id.to_string()),
        text: Set(text.to_string()),
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
                        let notes: Vec<serde_json::Value> = user  //Vec<note::Model>
                            .find_related(Note)
                            .into_json()
                            //WARNING: Add pagination
                            // .paginate(db, 50);
                            .all(db)
                            .await?;

                        return Ok(HttpResponse::Ok().json(notes))
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

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct DTONote {
    pub(crate) text: String,
}


