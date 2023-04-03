use crate::models::ServiceError;
use actix_web::{web, HttpRequest, HttpResponse};
mod controller;

pub fn init_general_handlers_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/ping").route(web::get().to(controller::ping)));
}

pub async fn p404(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    Err(ServiceError::not_found(&req, "Page not found.", true))
}
