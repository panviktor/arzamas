use actix_web::{HttpRequest, HttpResponse};
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{
    active_sessions,
    current_active_session,
    remove_active_session_token,
    remove_all_sessions_token
};

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