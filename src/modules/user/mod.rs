use actix_web::{guard, web};
use crate::modules::auth::middleware;

pub mod controller;

pub fn init_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .guard(guard::Header("content-type", "application/json"))
            .wrap(middleware::AuthCheckService)
            .service(
                web::resource("/logout")
                    .route(web::post().to(controller::logout))
            )
    );
}