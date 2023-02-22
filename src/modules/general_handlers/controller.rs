use actix_web::{HttpResponse};

pub async fn ping() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<h1>Server ok, how are you?</h1>")
}