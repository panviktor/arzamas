use crate::application::error::response_error::AppResponseError;
use actix_web::{web, HttpRequest, HttpResponse};

mod controllers;

pub fn init_general_handlers_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/ping").route(web::get().to(controllers::ping)));
}

pub async fn p404(req: HttpRequest) -> Result<HttpResponse, AppResponseError> {
    Err(AppResponseError::not_found(&req, "Page not found.", true))
}
