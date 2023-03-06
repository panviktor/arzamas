use actix_web::{HttpRequest, HttpResponse};
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{
    sessions_active_count
};

pub async fn logout(
    req: HttpRequest,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {

    let str = sessions_active_count(&req,&user.id).await.unwrap();

    // if let Some(current_token) = get_session_token_http_request(&req) {


    Ok(HttpResponse::Ok().json(str))
    // }

    // Err(ServiceError::unauthorized(
    //     &req,
    //     "Invalid logout.",
    //     true,
    // ))
}