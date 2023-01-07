use actix_web::{HttpRequest, HttpResponse};
use crate::models::ServiceError;

pub async fn ping() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<h1>Ok</h1>")
}