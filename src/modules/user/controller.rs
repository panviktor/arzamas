use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{
    try_active_sessions, try_current_active_session, try_remove_active_session_token,
    try_remove_all_sessions_token,
};
use crate::modules::user::models::{ChangeEmailParams, ChangePasswordParams, MnemonicConfirmation};
use actix_web::{web, HttpRequest, HttpResponse};

use crate::modules::user::service::{
    try_2fa_activate, try_2fa_add, try_2fa_remove, try_2fa_reset, try_about_me, try_add_email_2fa,
    try_change_email, try_change_password, try_get_security_settings, try_remove_email_2fa,
    try_resend_verify_email, try_update_security_settings,
};

/// Handler for getting information about the current user
#[utoipa::path(
    get,
    path = "/api/user/about-me",
    params(
         ("content-type" = String, Header, description = "application/json")
    ),
    responses(
        (status = 200, description = "User information retrieved successfully", body = AboutMeInformation),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn about_me(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    let info = try_about_me(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(info))
}

pub async fn logout(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    try_remove_active_session_token(&req).await?;
    Ok(HttpResponse::Ok().json("Logout from current session"))
}

pub async fn logout_all(user: LoginUser) -> Result<HttpResponse, ServiceError> {
    try_remove_all_sessions_token(&user.id).await?;
    Ok(HttpResponse::Ok().json("Logout from all sessions"))
}

pub async fn current_session(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    let session = try_current_active_session(&req).await?;
    Ok(HttpResponse::Ok().json(session))
}

pub async fn all_sessions(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    let sessions = try_active_sessions(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(sessions))
}

pub async fn change_password(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<ChangePasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    try_change_password(&req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("Password Changed Successfully."))
}

pub async fn change_email(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<ChangeEmailParams>,
) -> Result<HttpResponse, ServiceError> {
    try_change_email(&req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("Email Changed Successfully."))
}

pub async fn resend_verify_email(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    try_resend_verify_email(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("Email Verify Resend Successfully"))
}

pub async fn get_security_settings(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    let info = try_get_security_settings(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(info))
}

pub async fn update_security_settings(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    try_update_security_settings(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("get_security_settings"))
}

pub async fn add_email_2fa(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    try_add_email_2fa(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("Sending an authorization code by email is activated."))
}

pub async fn remove_email_2fa(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    try_remove_email_2fa(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("Sending an authorization code by email is disabled."))
}

pub async fn add_2fa(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    let json = try_2fa_add(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(json))
}

pub async fn activate_2fa(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<MnemonicConfirmation>,
) -> Result<HttpResponse, ServiceError> {
    try_2fa_activate(&req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("2FA Successfully Added:\
     Congratulations on successfully setting up two-factor authentication (2FA) for your account!\
     This additional layer of security will help protect your account and ensure that only authorized individuals can access it. \
     Remember to keep your 2FA device or app safe and secure."))
}

pub async fn reset_2fa(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    let json = try_2fa_reset(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(json))
}

pub async fn remove_2fa(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    try_2fa_remove(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("Remove 2FA Success: \
    Please keep in mind that disabling two-factor authentication (2FA) reduces the security of your account.\
    It is recommended to use alternative security measures such as strong passwords, regular account monitoring,\
    and enabling other security features provided by the platform to maintain the security of your account."))
}
