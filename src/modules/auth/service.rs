use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use deadpool_redis::Pool;

use entity::user;
use entity::user::Model as User;
use sea_orm::{ActiveModelTrait, Set};

use crate::core::constants::core_constants;
use crate::infrastructure::persistence::db::extract_db_connection;
use crate::application::error::response_error::AppResponseError;
use crate::modules::auth::credentials::{
    credential_validator_username_email, generate_password_hash, generate_user_id,
    validate_email_rules, validate_password_rules, validate_username_rules,
};
use crate::modules::auth::email::{
    send_password_reset_email, send_validate_email, verify_user_email,
};
use crate::modules::auth::models::{
    CreatedUserDTO, ForgotPasswordParams, LoginParams, LoginResponse, NewUserParams, OTPCode,
    ResetPasswordParams,
};
use crate::modules::auth::session::get_ip_addr;
use crate::modules::auth::totp::verify_otp_codes;
use crate::modules::auth::utils::{
    create_user_and_try_save, get_user_by_email, get_user_by_id, get_user_by_username,
    get_user_settings_by_id, handle_login_result, user_created_response,
    verify_password_reset_token,
};

pub(crate) async fn try_create_user(
    req: &HttpRequest,
    params: NewUserParams,
) -> Result<CreatedUserDTO, AppResponseError> {
    let db = extract_db_connection(req)?;

    if let Err(e) = validate_password_rules(&params.password, &params.password_confirm) {
        return Err(AppResponseError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }

    if let Err(e) = validate_username_rules(&params.username) {
        return Err(AppResponseError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }

    if let Err(e) = validate_email_rules(&params.email) {
        return Err(AppResponseError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }

    // check user doesn't already exist
    if get_user_by_username(&params.username, db)
        .await
        .map_err(|s| s.general(&req))?
        .is_some()
    {
        return Err(AppResponseError::bad_request(
            &req,
            &format!(
                "Cannot create user: {} as that username is taken",
                params.username
            ),
            true,
        ));
    }

    if get_user_by_email(&params.email, db)
        .await
        .map_err(|s| s.general(&req))?
        .is_some()
    {
        return Err(AppResponseError::bad_request(
            &req,
            &format!("Cannot create user for email: {} as that email is already associated with an account.", params.email),
            true,
        ));
    }

    let mut user_error: Option<AppResponseError> = None;
    let mut saved_user: Option<User> = None;
    let mut user_id: String;

    for i in 0..10 {
        user_id = generate_user_id().map_err(|s| s.general(&req))?;

        match create_user_and_try_save(&req, &user_id, &params).await {
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
        return Err(AppResponseError::general(
            req,
            format!("Error generating user ID: {}", e),
            false,
        ));
    }
    let saved_user = saved_user.expect("Error unwrap saved user");

    // Send a validation email
    send_validate_email(&saved_user.user_id, &saved_user.email, false, db)
        .await
        .map_err(|s| s.general(&req))?;

    Ok(user_created_response(&saved_user))
}

pub async fn try_send_restore_email(
    req: &HttpRequest,
    params: ForgotPasswordParams,
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;
    if let Err(e) = validate_username_rules(&params.username) {
        return Err(e.bad_request(&req));
    }
    // Check the password is valid
    if let Err(e) = validate_email_rules(&params.email) {
        return Err(e.bad_request(&req));
    }

    match get_user_by_username(&params.username, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        Some(user) => {
            if user.email == params.email {
                send_password_reset_email(&user.user_id, &user.email, db)
                    .await
                    .map_err(|s| AppResponseError::general(&req, s.message, false))?;
            }
        }
        None => {}
    };
    Ok(())
}

pub async fn try_reset_password(
    req: &HttpRequest,
    params: ResetPasswordParams,
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;
    let user = verify_password_reset_token(&params.token, db)
        .await
        .map_err(|s| s.general(req))?;

    // Check the new password is valid
    if let Err(e) = validate_password_rules(&params.password, &params.password_confirm) {
        return Err(e.bad_request(&req));
    }

    // check user matches the one from the token
    if user.user_id != params.user_id {
        return Err(AppResponseError::bad_request(
            &req,
            "User/token mismatch.",
            true,
        ));
    }

    if let Some(user) = get_user_by_id(&params.user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        let hash = generate_password_hash(&params.password).map_err(|s| s.general(&req))?;

        let mut active: user::ActiveModel = user.into();
        active.pass_hash = Set(hash.to_owned());
        active.updated_at = Set(Utc::now().naive_utc());
        active.update(db).await?;

        // Add optional invalidate all user session
        // based on user preferences
        // Send to email alert
    }

    Ok(())
}

pub async fn try_login_user(
    req: &HttpRequest,
    params: LoginParams,
) -> Result<HttpResponse, AppResponseError> {
    let db = extract_db_connection(req)?;
    // Check the username is valid
    if validate_username_rules(&params.identifier).is_err()
        && validate_email_rules(&params.identifier).is_err()
    {
        return Err(AppResponseError::bad_request(
            &req,
            "Invalid Username/Email",
            true,
        ));
    }

    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.password, &params.password) {
        return Err(e.bad_request(&req));
    }

    let result = credential_validator_username_email(&params.identifier, &params.password, db)
        .await
        .map_err(|s| AppResponseError::general(&req, s.message, true))?;

    if let Some(user) = result {
        if let Some(blocked_time) = user.login_blocked_until {
            if blocked_time > Utc::now().naive_utc() {
                return Err(AppResponseError::unauthorized(
                    &req,
                    "Too many attempts, try again later!",
                    true,
                ));
            }
        }

        let settings = get_user_settings_by_id(&user.user_id, db)
            .await
            .map_err(|s| AppResponseError::general(&req, s.message, true))?;

        return handle_login_result(&user.user_id, &user.email, settings, &req, &params, db).await;
    }

    Err(AppResponseError::unauthorized(
        &req,
        "Invalid credentials!",
        true,
    ))
}

pub async fn try_login_2fa(
    req: &HttpRequest,
    params: OTPCode,
) -> Result<LoginResponse, AppResponseError> {
    let login_ip = get_ip_addr(&req).map_err(|s| AppResponseError::general(&req, s.message, false))?;
    let db = extract_db_connection(req)?;

    let redis_pool = req
        .app_data::<web::Data<Pool>>() // Make sure Pool is the type of your Redis connection pool
        .ok_or_else(|| AppResponseError::general(&req, "Failed to extract Redis pool", true))?;

    let token = verify_otp_codes(
        params.email_code.as_deref(),
        params.app_code.as_deref(),
        &*params.user_id,
        &*login_ip,
        db,
        redis_pool,
    )
        .await
        .map_err(|s| AppResponseError::general(&req, s.message, true))?;

    Ok(LoginResponse::TokenResponse {
        token,
        token_type: core_constants::BEARER.to_string(),
    })
}

pub async fn try_verify_user_email(
    req: &HttpRequest,
    email: &str,
    token: &str,
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;
    verify_user_email(email, token, db)
        .await
        .map_err(|s| s.general(&req))
}
