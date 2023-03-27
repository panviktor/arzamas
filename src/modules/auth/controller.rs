use actix_web::{web, HttpResponse, HttpRequest};
use tracing::info;
use entity::user::{Model as User};

use crate::core::constants::core_constants;
use crate::models::{ServiceError};
use crate::modules::auth::credentials::{
    credential_validator_username_email,
    generate_user_id,
    validate_email_rules,
    validate_password_rules,
    validate_username_rules};
use crate::modules::auth::service::{
    create_user_and_try_save,
    get_user_by_email,
    get_user_by_username,
    try_reset_password,
    try_send_restore_email,
};
use crate::modules::auth::email::{
    validate_email,
    verify_user_email
};
use crate::modules::auth::models::{
    ForgotPasswordParams,
    LoginParams,
    LoginResponse,
    NewUserParams,
    OTPCode,
    ResetPasswordParams,
    VerifyEmailParams
};
use crate::modules::auth::session::{
    generate_session_token,
    get_ip_addr,
    get_user_agent
};
use crate::modules::auth::totp::{generate_totp_code, verify_email_otp_code};

pub async fn create_user(
    req: HttpRequest,
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
    let mut user_id: String;

    for i in 0..10 {
        user_id = generate_user_id().map_err(|s| s.general(&req))?;

        match create_user_and_try_save(&user_id, &params.0, &req).await {
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
    validate_email(&saved_user.user_id, &saved_user.email, false)
        .await
        .map_err(|s| s.general(&req))?;

    /// MARK: - Need refactoring
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!("
             User {},\n
             Was created {},\n
             A verification email has been sent to: {}. \n
             Follow the link in the message to verify your email.\n
             The link will only be valid for 24 hours.",
                       &saved_user.username,
                       &saved_user.created_at,
                       &saved_user.email
        )
        )
    )
}

pub async fn verify_email(
    req: HttpRequest,
    params: web::Json<VerifyEmailParams>
) -> Result<HttpResponse, ServiceError> {
    verify_user_email(&params.email, &params.email_token).await
        .map_err(|s| s.general(&req))?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn login(
    req: HttpRequest,
    params: web::Json<LoginParams>
) -> Result<HttpResponse, ServiceError> {
    // Check the username is valid
    if validate_username_rules(&params.identifier).is_err()
        && validate_email_rules(&params.identifier).is_err()
    {
        return Err(ServiceError::bad_request(
            &req,
            "Invalid Username/Email",
            true,
        ));
    }

    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.password, &params.password) {
        return Err(e.bad_request(&req));
    }

    let result =  credential_validator_username_email(&params.identifier, &params.password)
        .await
        .map_err(|s| s.general(&req))?;

    handle_login_result(result, &req, &params).await
}

pub async fn login_2fa(
    req: HttpRequest,
    params: web::Json<OTPCode>
) -> Result<HttpResponse, ServiceError> {
    let login_ip = get_ip_addr(&req)
        .map_err(|s| ServiceError::general(&req, s.message, false))?;

    let token = verify_email_otp_code(
        &params.code,
        &params.user_id,
        &login_ip
    ).await.map_err(|s| ServiceError::general(&req, s.message, true))?;

    let json_response = LoginResponse::TokenResponse {
        token,
        token_type: core_constants::BEARER.to_string(),
    };
    Ok(HttpResponse::Ok().json(json_response))
}

pub async fn forgot_password(
    req: HttpRequest,
    params: web::Json<ForgotPasswordParams>
) -> Result<HttpResponse, ServiceError> {
    try_send_restore_email(&req, params.0).await?;
    Ok(HttpResponse::Ok().json("A password reset request has been sent."))
}

pub async fn password_reset(
    req: HttpRequest,
    params: web::Json<ResetPasswordParams>
) -> Result<HttpResponse, ServiceError> {
    try_reset_password(&req, params.0).await?;
    Ok(HttpResponse::Ok().json("Password successfully reset."))
}

async fn handle_login_result(
    user_option: Option<User>,
    req: &HttpRequest,
    params: &LoginParams
) -> Result<HttpResponse, ServiceError> {
    if let Some(user) = user_option {
        let login_ip = get_ip_addr(req)
            .map_err(|s| ServiceError::general(req, s.message, false))?;
        let user_agent = get_user_agent(&req);
        let persistent = params.persist.unwrap_or(false);

        let json_response = if user.totp_active {
            generate_totp_code(
                &user.user_id,
                persistent,
                &user.email,
                &login_ip,
                &user_agent
            ).await.map_err(|s| ServiceError::general(&req, s.message, false))?;

            LoginResponse::OTPResponse { message: "The code has been sent to your email!".to_string() }
        } else {
            let token = generate_session_token(
                &user.user_id,
                persistent,
                &login_ip,
                &user_agent,
            ).await.map_err(|s| ServiceError::general(&req, s.message, false))?;
            info!("Successfully generate session token in user: {}", params.identifier);

            LoginResponse::TokenResponse {
                token,
                token_type: core_constants::BEARER.to_string(),
            }
        };

        Ok(HttpResponse::Ok().json(json_response))
    } else {
        info!("Invalid credentials: {}", &params.identifier);
        Err(ServiceError::unauthorized(&req, "Invalid credentials.", true))
    }
}