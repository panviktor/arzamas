use crate::application::error::service_error::ServiceError;
use actix_web::{web, HttpRequest, HttpResponse};

mod controllers;

pub fn init_general_handlers_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/ping").route(web::get().to(controllers::ping)));
}

pub async fn p404(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    Err(ServiceError::not_found(&req, "Page not found.", true))
}
