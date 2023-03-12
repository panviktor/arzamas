use actix_web::{HttpRequest, HttpResponse};
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{active_sessions, current_active_session};

pub async fn logout(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {



    // if let Some(current_token) = get_session_token_http_request(&req) {


    Ok(HttpResponse::Ok().json("str"))
    // }

    // Err(ServiceError::unauthorized(
    //     &req,
    //     "Invalid logout.",
    //     true,
    // ))
}

pub async fn logout_all(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {

    Ok(HttpResponse::Ok().json("str"))
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