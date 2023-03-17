use actix_web::{HttpRequest, HttpResponse, web};
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{
    try_active_sessions,
    try_current_active_session,
    try_remove_active_session_token,
    try_remove_all_sessions_token
};

use crate::modules::user::service::{
    ChangeEmailParams,
    ChangePasswordParams,
    try_about_me,
    try_change_email,
    try_change_password,
    try_resend_verify_email
};

pub async fn about_me(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    let info = try_about_me(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(info))
}

pub async fn logout(
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    try_remove_active_session_token(&req).await?;
    Ok(HttpResponse::Ok().json("Logout from current session"))
}

pub async fn logout_all(
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    try_remove_all_sessions_token(&user.id).await?;
    Ok(HttpResponse::Ok().json("Logout from all sessions"))
}

pub async fn current_session(
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    let session = try_current_active_session(&req).await?;
    Ok(HttpResponse::Ok().json(session))
}

pub async fn all_sessions(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    let sessions = try_active_sessions(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(sessions))
}

pub async fn change_password(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<ChangePasswordParams>
) -> Result<HttpResponse, ServiceError> {
    try_change_password(&req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("Password Changed Successfully."))
}

pub async fn change_email(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<ChangeEmailParams>
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