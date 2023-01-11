use actix_web::{web, HttpResponse, HttpRequest};
use chrono::{DateTime, Utc};
use sea_orm::{DbConn, EntityTrait, NotSet, Set};
use serde::{Deserialize, Serialize};
use entity::user;
use crate::models::{ServiceError};
use crate::modules::auth::credentials::{generate_password_hash, generate_user_id, validate_email_rules, validate_password_rules, validate_username_rules};
use crate::modules::auth::service::{get_user_by_email, get_user_by_username};
use crate::core::db::DB;

pub async fn create_user(
    mut req: HttpRequest,
    params: web::Json<NewUserParams>
) -> Result<HttpResponse, ServiceError> {

    if let Err(e) = validate_password_rules(&params.password, &params.password_confirm) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }

    if let Err(e) = validate_username_rules(&params.username) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }

    if let Err(e) = validate_email_rules(&params.email) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }

    // check user doesn't already exist
    if get_user_by_username(&params.username)
        .await
        .map_err(|s| s.general(&req))?
        .is_some()
    {
        return Err(ServiceError::bad_request(
            &req,
            &format!(
                "Cannot create user: {} as that username is taken",
                params.username
            ),
            true,
        ));
    }

    if get_user_by_email(&params.email)
        .await
        .map_err(|s| s.general(&req))?
        .is_some()
    {
        return Err(ServiceError::bad_request(
            &req,
            &format!("Cannot create user for email: {} as that email is already associated with an account.", params.email),
            true,
        ));
    }

    // create password hash
    let hash = generate_password_hash(&params.password).map_err(|s| s.general(&req))?;

    let id = "123123";

    // insert user
    let db = &*DB;

    let _ = user::Entity::insert(user::ActiveModel {
        user_id: Set(id.to_string()),
        email: Set(params.0.email.to_string()),
        username: Set(params.0.username.to_string()),
        pass_hash: Set(hash.to_string()),
        totp_active: Set(true),
        totp_token: NotSet,
        totp_backups: NotSet,
        created_at: Set( Utc::now().naive_utc()),
        ..Default::default()
    })
        .exec(db)
        .await
        .map_err (|e| {
            println!("{}", e.to_string());
        });





    Ok(HttpResponse::Ok().finish())
}

pub async fn find_user(
    conn: web::Data<DbConn>,
    data: web::Json<NewUserParams>
) ->  Result<HttpResponse, ServiceError> {
    // let response = find_user_by_id_from_bd(&conn, &data).await?;
    // Ok(response)


    Ok(HttpResponse::Ok().finish())
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct NewUserParams {
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) password_confirm: String,
}