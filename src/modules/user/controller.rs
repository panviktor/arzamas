use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{
    try_active_sessions, try_current_active_session, try_remove_active_session_token,
    try_remove_all_sessions_token,
};
use actix_web::{web, HttpRequest, HttpResponse};

use crate::modules::user::service::{
    try_2fa_add, try_2fa_remove, try_2fa_reset, try_about_me, try_change_email,
    try_change_password, try_resend_verify_email, ChangeEmailParams, ChangePasswordParams,
};

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
    // try_2fa_add(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("get_security_settings"))
}

pub async fn update_security_settings(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    // try_2fa_add(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("get_security_settings"))
}

pub async fn add_email_2fa(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    // try_2fa_add(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("add_email_2fa"))
}

pub async fn remove_email_2fa(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    // try_2fa_add(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("remove_email_2fa"))
}

pub async fn add_2fa(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    try_2fa_add(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("Add 2fa"))
}

pub async fn reset_2fa(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    try_2fa_reset(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("Reset 2fa"))
}

pub async fn remove_2fa(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    try_2fa_remove(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json("Remove 2fa"))
}
