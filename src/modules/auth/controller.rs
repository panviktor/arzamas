use actix_web::{web, HttpResponse};
use sea_orm::{ DbConn, };
use serde::{Deserialize, Serialize};
use crate::models::ServiceError;

use crate::modules::auth::service::insert_user;
use crate::modules::auth::service::find_user_by_id_from_bd;

pub async fn create_user(
    conn: web::Data<DbConn>,
    data: web::Json<NewUserParams>
) ->  Result<HttpResponse, ServiceError> {
     let response = insert_user(&conn, &data).await?;
     Ok(response)
}

pub async fn find_user(
    conn: web::Data<DbConn>,
    data: web::Json<NewUserParams>
) ->  Result<HttpResponse, ServiceError> {
    let response = find_user_by_id_from_bd(&conn, &data).await?;
    Ok(response)
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct NewUserParams {
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) password_confirm: String,
}