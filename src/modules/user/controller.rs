use actix_web::{HttpRequest, HttpResponse, web};
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{
    active_sessions,
    current_active_session,
    remove_active_session_token,
    remove_all_sessions_token
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
    remove_active_session_token(&req).await?;
    Ok(HttpResponse::Ok().json("logout from current session"))
}

pub async fn logout_all(
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    remove_all_sessions_token(&user.id).await?;
    Ok(HttpResponse::Ok().json("logout from all sessions"))
}

pub async fn current_session(
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    let session = current_active_session(&req).await?;
    Ok(HttpResponse::Ok().json(session))
}

pub async fn all_sessions(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    let sessions = active_sessions(&req, &user.id).await?;
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