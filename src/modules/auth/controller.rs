use actix_web::{web, HttpResponse, HttpRequest};
use sea_orm::{DbConn, EntityTrait};
use serde::{Deserialize, Serialize};
use entity::user::{Model as User};
use crate::models::{ServiceError};
use crate::modules::auth::credentials::{
    generate_user_id,
    validate_email_rules,
    validate_password_rules,
    validate_username_rules
};
use crate::modules::auth::service::{
    create_user_and_try_save,
    get_user_by_email, get_user_by_username
};
use crate::modules::auth::email::validate_email;

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

    let mut user_error: Option<ServiceError> = None;
    let mut saved_user: Option<User> = None;
    let mut user_id = "".to_string();

    for i in 0..10 {
        user_id = generate_user_id().map_err(|s| s.general(&req))?;

        match  create_user_and_try_save(&user_id, &params.0, &req).await {
            Ok(user) => {
                saved_user = Some(user);
                break;
            }
            Err(err) => {
                log::warn!(
                    "Problem creating user ID for new user {} (attempt {}/10): {}",
                    user_id,
                    i + 1,
                    err
                );
                user_error = Some(err);
            }
        }
    }

    if let Some(e) = user_error {
        return Err(ServiceError::general(
            &req,
            format!("Error generating user ID: {}", e),
            false,
        ));
    }

    let saved_user = saved_user.expect("Error unwrap saved user");

    // Send a validation email
    validate_email(&saved_user.user_id, &saved_user.email)
        .await
        .map_err(|s| s.general(&req))?;

    /// MARK: - Need refactoring
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!("
             User {},\

             Was created {},

             A verification email has been sent to: {}. \

             Follow the link in the message to verify your email.

             The link will only be valid for 24 hours.",
                       &saved_user.username,
                       &saved_user.created_at,
                       &saved_user.email
        )
        )
    )
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